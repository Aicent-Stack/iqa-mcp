"""iqa-mcp -- the IQA attestation primitives, exposed as MCP tools.

A thin, stateless wrapper around the published ``iqa-org`` reference
implementation (v1.3.1). Every tool runs offline: no network, no
accounts, no key storage. Fail-closed: malformed input is a REJECT
result, never a normalised partial answer.

Tools
-----
derive_route_shard(authority)
    SHA-256(authority), first 16 bytes, lowercase hex -- the derived,
    action-independent intent address (SPEC sec. 3).
parse_envelope(envelope_hex)
    Structural decode of one AE-128 frame. No key needed; fails closed
    on every layout rule of the companion draft.
verify_envelope(envelope_hex, organ_key, now, check_lease)
    Full AE-128 verification: constant-time HMAC over the whole frame
    (attestation zeroed) plus the lease check. REJECT is a result.
published_vector()
    The published AE128-VECTOR-1 (authority, test key, lease, frame
    hex) so any MCP client can reproduce [PASS] byte for byte.

Run
---
    python server.py          # stdio transport
"""

import json

from mcp.server.mcpserver import MCPServer

from iqa import envelope
from iqa.envelope import (
    VECTOR_1_AUTHORITY,
    VECTOR_1_FRAME_HEX,
    VECTOR_1_KEY,
    VECTOR_1_LEASE,
    VECTOR_1_NONCE,
    VECTOR_1_ORGAN,
    VECTOR_1_STANDING,
    vector_1_frame,
)

mcp = MCPServer(
    "iqa",
    title="iqa attestation tools",
    description="Offline, fail-closed IQA attestation primitives: derived intent addressing and AE-128 envelope verification, wrapping the published iqa-org 1.3.1 reference implementation.",
)


def _decode_hex(envelope_hex: str) -> bytes:
    if not isinstance(envelope_hex, str):
        raise envelope.EnvelopeError("envelope must be a hex string")
    cleaned = envelope_hex.strip().lower().replace(" ", "").replace("\n", "")
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise envelope.EnvelopeError(f"invalid hex: {exc}") from exc
    return raw


def _frame_json(frame: dict) -> str:
    out = dict(frame)
    out["intent_shard"] = out["intent_shard"].hex()
    out["attestation"] = out["attestation"].hex()
    return json.dumps(out, indent=2)


@mcp.tool(description="Derive the ROUTE_SHARD / intent shard for an authority: SHA-256 of the exact authority string, first 16 bytes, lowercase hex. Deterministic, offline, action-independent (SPEC sec. 3). No lookup, no registry, no network call.")
def derive_route_shard(authority: str) -> str:
    """Derive the ROUTE_SHARD / intent shard for an authority."""
    try:
        return envelope.intent_shard_hex(authority)
    except envelope.EnvelopeError as exc:
        return json.dumps({"ok": False, "reject": str(exc)})


@mcp.tool(description="Structural decode of one AE-128 attestation envelope (128 bytes, hex). No organ key needed. Fails closed on every layout rule of the companion draft sec. 2/sec. 4 -- malformed input is never normalised into a partial result.")
def parse_envelope(envelope_hex: str) -> str:
    """Structural decode of one AE-128 attestation envelope (128 bytes, hex). No organ key needed. Fails closed on every layout rule of the companion draft sec. 2/sec. 4 -- malformed input is never normalised into a partial result."""
    try:
        frame = envelope.parse(_decode_hex(envelope_hex))
    except envelope.EnvelopeError as exc:
        return json.dumps({"ok": False, "reject": str(exc)})
    return json.dumps({"ok": True, "frame": json.loads(_frame_json(frame))}, indent=2)


@mcp.tool(description="Full AE-128 verification (companion draft sec. 4): constant-time HMAC-SHA256 over the whole 128-byte frame with the attestation field zeroed, plus the optional lease check. organ_key is the organ's shared test/deployment key (this server is stateless and stores nothing). REJECT is a result, not an error: a flipped byte anywhere breaks the MAC.")
def verify_envelope(envelope_hex: str, organ_key: str, now=None, check_lease: bool = True) -> str:
    """Full AE-128 verification (companion draft sec. 4): constant-time HMAC-SHA256 over the whole 128-byte frame with the attestation field zeroed, plus the optional lease check. organ_key is the organ's shared test/deployment key (this server is stateless and stores nothing). REJECT is a result, not an error: a flipped byte anywhere breaks the MAC."""
    try:
        raw = _decode_hex(envelope_hex)
    except envelope.EnvelopeError as exc:
        return json.dumps({"ok": False, "reject": str(exc)})
    if now is not None and not isinstance(now, (int, float)):
        return json.dumps({"ok": False, "reject": f"now must be a unix timestamp number, got {type(now).__name__}"})
    ok, reason, frame = envelope.verify(raw, organ_key.encode("ascii"), now=now, check_lease=check_lease)
    if not ok:
        return json.dumps({"ok": False, "reject": reason})
    out = json.loads(_frame_json(frame))
    out["lease_expiry_iso"] = __import__("datetime").datetime.fromtimestamp(
        out["lease_expiry"], __import__("datetime").timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return json.dumps({"ok": True, "reason": reason, "frame": out}, indent=2)


@mcp.tool(description="Return AE128-VECTOR-1, the published conformance vector (companion draft sec. 6): the example authority, the documented test organ key, the lease, and the full 128-byte frame as hex. Feed these into verify_envelope and you must get [PASS] -- byte for byte, offline.")
def published_vector() -> str:
    """Return AE128-VECTOR-1, the published conformance vector (companion draft sec. 6): the example authority, the documented test organ key, the lease, and the full 128-byte frame as hex. Feed these into verify_envelope and you must get [PASS] -- byte for byte, offline."""
    return json.dumps({
        "authority": VECTOR_1_AUTHORITY,
        "organ_key": VECTOR_1_KEY.decode("ascii"),
        "lease_expiry": VECTOR_1_LEASE,
        "standing": VECTOR_1_STANDING,
        "organ": VECTOR_1_ORGAN,
        "nonce": VECTOR_1_NONCE,
        "frame_hex": VECTOR_1_FRAME_HEX,
        "expected": "verify_envelope(frame_hex, organ_key) -> [PASS] standing=Radiant",
    }, indent=2)


if __name__ == "__main__":
    mcp.run()
