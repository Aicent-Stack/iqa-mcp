# Gateway response binding — end-to-end offline verification

Answers the request in [docker/mcp-gateway#596](https://github.com/docker/mcp-gateway/discussions/596):
connect the flipped-byte MAC check to **response verification**, with one
end-to-end offline example showing how an authenticated envelope binds the
**actual tool response** to the **intended server**.

```
pip install "iqa-org[ed25519]"
python demo.py
```

No network. No directory. No issuer. Local clock only.

## The flow

```
SERVER (signs every tool response)                GATEWAY (verifies, offline)
                                                  policy pinned out-of-band:
authority = invoice-tools.gateway-demo.dev        { authority, route, organ,
route      = derive_route_hex(authority)            signer_aid }
key       = organ key (Ed25519)

response ── sha256 ──> resp_aid                   1. route derivation matches
claim  = iqa://<resp_aid>.forge.iqa                  the intended server
envelope = Ed25519 seal(claim, key)               2. sha256(actual response)[:32]
   ts, nonce INSIDE the signature                    == envelope subject
                                                  3. envelope.aid == pinned
wire = { response, envelope } ──────────────────►    signer AID (self-certifying)
                                                  4. Ed25519 seal verifies
                                                  5. freshness window (120 s)

                                                  all five pass → ACCEPT
                                                  any step fails → REJECT
```

## The flipped-byte check, connected

`demo.py` T1 flips **one byte inside the response payload** (inside
`412.50`). The envelope itself is untouched and its signature still
verifies — the response-binding step is what catches it:

```
T1 response: one byte flipped -> REJECT
    [x] route derivation matches the intended server
    [ ] response bytes bound to envelope subject   <- caught here
    [x] signer is the pinned server key (AID)
    [x] Ed25519 seal verifies
    [x] freshness window (120 s, live mode)
```

Full matrix the demo asserts (`ALL CHECKS BEHAVED AS DESIGNED`):

| case                          | caught by            |
|-------------------------------|----------------------|
| T1 one byte flipped in response | response binding (2) |
| T2 standing flipped radiant→ghost inside the envelope | seal (4) — ts+nonce are inside the signature |
| T3 impostor: own key, same organ label | server binding (3) — AID pin |
| T4 envelope replayed 600 s later | freshness (5) — live mode |

## What the gateway embeds

`verify_tool_response(response_bytes, envelope, policy, now)` in `demo.py`
is the whole check — about twenty lines over the published `iqa-org` API
(`derive_route_hex`, `verify_envelope`, one SHA-256). It is a pure function:
no I/O, no global state, fail-closed on every step. The natural wiring in a
gateway is a response interceptor / middleware hook that runs it after the
tool call returns and before the answer reaches the agent; on any `False`
the response is dropped, never passed through.

The `policy` is pinned by the gateway operator out of band (config file —
data, not a lookup): the server's authority, the route derived from it, and
the signer AID. Nothing in the verify path touches the network; the only
time source is the gateway's own clock (freshness window 120 s, per the
envelope spec — archived seals use `check_freshness=False` instead).

## Properties

- **Self-certifying**: `AID = SHA-256(public key)`, recomputed by the
  verifier from the in-band key. Lose the key, lose the identity — there is
  no operator who can restore it.
- **Closed sets**: `organ` ∈ {forge, tss, gateway}, `standing` ∈
  {ghost, probation, radiant, genesis} — enforced by the codec, not by
  convention.
- **Domain separation**: the signing input is prefixed `iqa-attest-v1\n` —
  a signature made for one scheme can never be replayed as the other.
- **The response is hashed, not hidden**: the envelope names the response
  (`sha256[:32]`); confidentiality is a separate concern and deliberately
  not claimed here.

## Provenance

- Envelope API: `iqa-org` 1.3.1 — [PyPI](https://pypi.org/project/iqa-org/) ·
  [npm](https://www.npmjs.com/package/@aicent/iqa) ·
  [crates.io](https://crates.io/crates/iqa-org)
- Specification: [draft-li-rttp-iqa-addressing](https://datatracker.ietf.org/doc/draft-li-rttp-iqa-addressing/)
  (IETF Independent Submission stream, in review)
- Gateway-side tooling: [iqa-mcp](https://github.com/Aicent-Stack/iqa-mcp)
  (`derive_route_shard` / `parse_envelope` / `verify_envelope` /
  `published_vector`)
- Every release artifact is sealed by the same envelope API and verifiable
  offline: [iqa.org/attestations/](https://iqa.org/attestations/)
