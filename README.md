# iqa-mcp

The IQA attestation primitives — derived intent addressing and AE-128
envelope verification — exposed as [Model Context Protocol](https://modelcontextprotocol.io)
tools, so any MCP agent (Claude Desktop, Cline, your own client, an
Uber-style MCP Gateway) can verify trust **offline, fail-closed**.

A thin, stateless wrapper around the published
[`iqa-org`](https://pypi.org/project/iqa-org/1.3.1/) 1.3.1 reference
implementation. No network. No accounts. No key storage. No state.

## Tools

| Tool | Input | Returns | Key needed |
|------|-------|---------|------------|
| `derive_route_shard` | authority string | `SHA-256(authority)[0:16]` hex — the derived, action-independent intent address | no |
| `parse_envelope` | AE-128 frame hex | structural decode: version, lease, shard, organ, nonce, standing — fails closed on every layout rule | no |
| `verify_envelope` | frame hex + organ key | full verification: constant-time HMAC-SHA256 over the whole 128-byte frame (attestation zeroed) + lease check. **REJECT is a result, not an error** | yes (caller-supplied) |
| `published_vector` | — | the published AE128-VECTOR-1 (authority, test key, frame hex) for byte-for-byte self-test | — |

## Run

```bash
pip install "iqa-org>=1.3.1" "mcp>=2"
python server.py            # stdio transport
```

MCP client configuration (Claude Desktop / Cline style):

```json
{
  "mcpServers": {
    "iqa": {
      "command": "python",
      "args": ["/path/to/server.py"]
    }
  }
}
```

## Self-test

```bash
python test_mcp.py
# [PASS] 1 · list_tools        -> 4 tools
# [PASS] 2 · derive_route_shard -> 5c378581f92754d0bc88adaed84b7c5a
# [PASS] 3 · published_vector   -> f3b2a1c4.pillar.example
# [PASS] 4 · parse_envelope     -> standing radiant
# [PASS] 5 · verify_envelope    -> [PASS] radiant · nonce 1
# [PASS] 6 · tampered frame     -> REJECT (HMAC mismatch)
# [PASS] 7 · malformed hex      -> REJECT
# ALL 7/7 PASS
```

Test 6 is the point: **flip one byte of the standing field and the
frame dies** — attestation does not verify. Fail-closed, over the wire.

## Why

Agent platforms are converging on MCP as the tool-calling layer
(Microsoft's agent OS, Google's Antigravity, Uber's MCP Gateway with
800+ servers and 5000+ tools). The missing layer is trust semantics:
*what intent is being addressed* and *whether the counterparty has
standing* — verifiable without a network call. These four tools make
that layer native to any MCP agent.

Design invariants, inherited from the schemes:

- **Zero-parser**: fixed offsets, no TLV, no heap-shaped parsing.
- **Fail-closed**: malformed input is a REJECT result, never a
  normalised partial answer.
- **Offline**: verification needs the frame, the key, and a hash
  function. Nothing else.
- **Stateless**: the server stores nothing; the organ key is passed
  per call by the client and never persisted.

## Status

Working implementation, protocol-tested (stdio, MCP 2.x SDK). Not yet
published to PyPI as its own distribution — packaging/registry
placement is a pending decision. The underlying schemes are
`iqa-org` 1.3.1 (four registries) with the merged Internet-Draft
`draft-li-rttp-iqa-addressing-00` in Independent Submission review.

Public record: <https://iqa.org/brief/>
