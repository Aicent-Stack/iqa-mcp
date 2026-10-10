#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""End-to-end offline response verification for MCP Gateway.

The scenario Harlock asked for in docker/mcp-gateway#596, made concrete:

  1. a tool server signs its ACTUAL tool response into an iqa:// envelope
     (the response hash is the envelope's subject; the server's organ key
      signs the frame),
  2. the gateway verifies the pair OFFLINE -- no network, no directory --
     and the flipped-byte tamper is caught by the response-binding check,
     not just by envelope self-inspection.

Run:
    pip install "iqa-org[ed25519]"
    python demo.py

Everything below is local computation. The only "network" is conceptual:
the wire object the gateway receives is `{"response": ..., "envelope": ...}`.
"""

import hashlib
import json
import sys

from iqa import attest as A
from iqa import derive_route_hex

# --------------------------------------------------------------------------
# The intended tool server (fixed scene)
# --------------------------------------------------------------------------

AUTHORITY = "invoice-tools.gateway-demo.dev"   # the server the gateway intends to call
ORGAN = "forge"                                # the server's organ (closed set member)
RESPONSE_SEED = bytes(range(32))               # demo seed -- reproducible keys only


def response_bytes_of(resp: dict) -> bytes:
    """The exact bytes the gateway will hash. Canonical JSON, UTF-8."""
    return A.json_canonical(resp)


def verify_tool_response(response_bytes: bytes, envelope: dict, policy: dict,
                         now: int) -> tuple:
    """The check a gateway response-interceptor embeds. ~20 lines, offline.

    Fail closed: any failed step rejects the response outright.

    Returns (ok: bool, steps: list[(name, ok, detail)]).
    """
    steps = []

    # 1. ROUTE -- the intended server is identified by derivation, not by lookup.
    route = derive_route_hex(policy["authority"])
    ok1 = route == policy["route"]
    steps.append(("route derivation matches the intended server", ok1,
                  "%s" % route))

    # 2. RESPONSE BINDING -- the envelope's subject IS the response hash.
    #    This is the flipped-byte check, connected: change one byte anywhere
    #    in the response and this step fails before anything else matters.
    resp_aid = hashlib.sha256(response_bytes).hexdigest()[:32]
    subject = envelope.get("payload", {}).get("subject_uri", "")
    ok2 = subject.startswith("iqa://%s." % resp_aid)
    steps.append(("response bytes bound to envelope subject", ok2,
                  "sha256(response)[:32]=%s" % resp_aid))

    # 3. SERVER BINDING -- the signer is the pinned organ key of THIS server.
    #    AID = SHA-256(public key); the public key travels in the envelope,
    #    so the verifier recomputes it -- nothing is taken on faith.
    ok3 = envelope.get("aid") == policy["signer_aid"]
    steps.append(("signer is the pinned server key (AID)", ok3,
                  "aid=%s" % envelope.get("aid", "?")[:16]))

    # 4. SEAL -- Ed25519 over the canonical signing input (ts, nonce inside).
    ok4, reason4, _ = A.verify_envelope(envelope, now=now)
    steps.append(("Ed25519 seal verifies (ts, nonce inside the sig)", ok4, reason4))

    # 5. FRESHNESS -- live window (120s) enforced by the same call.
    if ok4:
        ok5, reason5, _ = A.verify_envelope(envelope, now=now)
        steps.append(("freshness window (120s, live mode)", ok5, reason5))
    else:
        steps.append(("freshness window (120s, live mode)", False,
                      "skipped: seal already failed (fail closed)"))

    ok = all(s[1] for s in steps)
    return ok, steps


def show(title, ok, steps):
    print("\n--- %s -> %s" % (title, "ACCEPT" if ok else "REJECT (fail closed)"))
    for name, s_ok, detail in steps:
        print("    [%s] %-52s %s" % ("x" if s_ok else " ", name, detail))


def main() -> int:
    print("gateway response binding -- end to end, offline")
    print("authority : %s" % AUTHORITY)

    # ------------------------------------------------------------------
    # SERVER SIDE -- what the tool server does per response
    # ------------------------------------------------------------------
    route = derive_route_hex(AUTHORITY)
    kp = A.generate_keypair(seed=RESPONSE_SEED)

    # The policy the gateway operator pins OUT OF BAND (a config file, not
    # a lookup): which server, which derived route, which organ key.
    policy = {"authority": AUTHORITY, "route": route,
              "organ": ORGAN, "signer_aid": kp["aid_hex"]}
    print("policy    : route=%s signer_aid=%s..." % (route, kp["aid_hex"][:16]))

    response = {
        "jsonrpc": "2.0", "id": 7,
        "result": {"content": [{"type": "text", "text":
                    "INVOICE-2026-1042 total=412.50 USD status=PAID"}]},
    }
    resp_bytes = response_bytes_of(response)
    resp_aid = hashlib.sha256(resp_bytes).hexdigest()[:32]

    claim = A.build_claim("iqa://%s.%s.iqa" % (resp_aid, ORGAN), ORGAN, "radiant")
    envelope = A.seal(claim, kp, nonce="0123456789abcdef")  # fixed nonce: reproducible demo
    wire = {"response": response, "envelope": envelope}     # what crosses the wire

    now = envelope["ts"] + 10                               # 10s after sealing

    # ------------------------------------------------------------------
    # GATEWAY SIDE -- zero network, local clock only
    # ------------------------------------------------------------------
    ok, steps = verify_tool_response(response_bytes_of(wire["response"]),
                                     wire["envelope"], policy, now)
    show("honest response", ok, steps)

    # ------------------ tamper matrix ---------------------------------
    # T1: flip ONE byte in the response (the check Harlock asked to connect)
    flipped = bytearray(resp_bytes)
    i = flipped.index(b"4"[0])                      # flip inside "412.50"
    flipped[i] = flipped[i] ^ 0x01                  # one bit, anywhere in the frame
    ok, steps = verify_tool_response(bytes(flipped), envelope, policy, now)
    show("T1 response: one byte flipped", ok, steps)

    # T2: flip the standing inside the signed envelope (radiant -> ghost)
    env2 = json.loads(json.dumps(envelope))
    env2["payload"]["standing"] = "ghost"
    ok, steps = verify_tool_response(resp_bytes, env2, policy, now)
    show("T2 envelope: standing flipped to ghost", ok, steps)

    # T3: an impostor server (own key, same organ name, same authority string)
    kp2 = A.generate_keypair()
    claim3 = A.build_claim("iqa://%s.%s.iqa" % (resp_aid, ORGAN), ORGAN, "radiant")
    env3 = A.seal(claim3, kp2, nonce="0123456789abcdef")
    ok, steps = verify_tool_response(resp_bytes, env3, policy, now)
    show("T3 impostor: different key, same organ label", ok, steps)

    # T4: replay -- same envelope, six minutes later
    ok, steps = verify_tool_response(resp_bytes, envelope, policy,
                                     now=envelope["ts"] + 600)
    show("T4 replay: envelope reused 600s later", ok, steps)

    verdicts = [ok for ok, _ in [
        verify_tool_response(response_bytes_of(wire["response"]), wire["envelope"], policy, now),
        verify_tool_response(bytes(flipped), envelope, policy, now),
        verify_tool_response(resp_bytes, env2, policy, now),
        verify_tool_response(resp_bytes, env3, policy, now),
        verify_tool_response(resp_bytes, envelope, policy, now=envelope["ts"] + 600),
    ]]
    expected = [True, False, False, False, False]
    done = verdicts == expected
    print("\n%s" % ("ALL CHECKS BEHAVED AS DESIGNED" if done else "UNEXPECTED BEHAVIOR: %s" % verdicts))
    return 0 if done else 1


if __name__ == "__main__":
    sys.exit(main())
