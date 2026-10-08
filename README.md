# iqa-mcp

[![PyPI](https://img.shields.io/pypi/v/iqa-mcp)](https://pypi.org/project/iqa-mcp/)
[![License](https://img.shields.io/pypi/l/iqa-mcp)](https://github.com/Aicent-Stack/iqa-mcp/blob/main/LICENSE)
[![self-test](https://github.com/Aicent-Stack/iqa-mcp/actions/workflows/self-test.yml/badge.svg)](https://github.com/Aicent-Stack/iqa-mcp/actions/workflows/self-test.yml)

The IQA attestation primitives — derived intent addressing and AE-128
envelope verification — exposed as Model Context Protocol tools, so any
MCP agent (Claude Desktop, Cline, your own client, an Uber-style MCP
Gateway) can verify trust offline, fail-closed.

A thin, stateless wrapper around the published `iqa-org 1.3.1` reference
implementation. No network. No accounts. No key storage. No state.

**PyPI** · [iqa-mcp 0.1.0](https://pypi.org/project/iqa-mcp/) · Apache-2.0
**Spec** · [draft-li-rttp-iqa-addressing](https://datatracker.ietf.org/doc/draft-li-rttp-iqa-addressing/) — Independent Submission, in review
**Landing page** · [iqa.org/MCP/](https://iqa.org/MCP/)
**Listings** · [ModelScope MCP 广场](https://modelscope.cn/mcp/servers/AicentStack/iqa-mcp)

---

## Why

Agent platforms are converging on MCP as the tool-calling layer, at
industrial scale. What none of them standardize is trust semantics:
what intent is being addressed, and whether the counterparty holds
standing — verifiable without a network call. These four tools make
that layer native to any MCP agent.

## Install

Requires Python ≥ 3.11.

```bash
# from PyPI — installs the `iqa-mcp` console command
pip install iqa-mcp

# or run from source
pip install "iqa-org>=1.3.1" "mcp>=2"
python server.py            # stdio transport
```

MCP client configuration (Claude Desktop / Cline style):

```json
{
  "mcpServers": {
    "iqa": {
      "command": "iqa-mcp"
    }
  }
}
```

(From source, use `"command": "python", "args": ["/path/to/server.py"]`
instead.)

---

## Tools

| Tool | Input | Returns | Key needed |
|---|---|---|---|
| `derive_route_shard` | authority string | `SHA-256(authority)[0:16]` hex — the derived, action-independent intent address | no |
| `parse_envelope` | AE-128 frame hex | structural decode: version, lease, shard, organ, nonce, standing — fails closed on every layout rule | no |
| `verify_envelope` | frame hex + organ key | full verification: constant-time HMAC-SHA256 over the whole 128-byte frame (attestation zeroed) + lease check. REJECT is a result, not an error | yes (caller-supplied) |
| `published_vector` | — | the published AE128-VECTOR-1 (authority, test key, frame hex — see [iqa-org](https://github.com/Aicent-Stack/iqa-org)) for byte-for-byte self-test | — |

## Try it in thirty seconds

```text
published_vector            -> AE128-VECTOR-1: authority + test key + frame hex
parse_envelope(frame)       -> standing radiant · nonce 1 · lease unexpired
verify_envelope(frame, key) -> PASS
flip one byte of standing   -> REJECT (HMAC mismatch)
```

That last line is the point: tampering is not detected by anyone
watching — the frame simply stops verifying, offline, for any verifier,
forever.

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

---

## Design invariants

Inherited from the schemes:

- **Zero-parser** — fixed offsets, no TLV, no heap-shaped parsing.
- **Fail-closed** — malformed input is a REJECT result, never a
  normalised partial answer.
- **Offline** — verification needs the frame, the key, and a hash
  function. Nothing else.
- **Stateless** — the server stores nothing; the organ key is passed per
  call by the client and never persisted.

## What this is not

Stated plainly, because evidence tooling that oversells is just
marketing:

- **Not real-time governance.** Gateways and policy engines decide in
  the moment; this server proves after the fact. The two compose; neither
  replaces the other.
- **Not a delegation scheme.** v1.3.x intentionally specifies no
  delegation semantics — see the draft's honest-boundary notes.
- **Not a key custodian.** The organ key never touches this server's
  state; verification is caller-supplied, per call. Never pass a
  production organ key through a host you do not control — whoever sees
  the key holds the verification power.
- **Not a benchmark.** The demos at iqa.org execute real WebCrypto in
  the browser; this server wraps the same published primitives.

---

## Status

- **Published**: [`iqa-mcp 0.1.0` on PyPI](https://pypi.org/project/iqa-mcp/) (2026-10-08).
- **Transport**: stdio. A hosted streamable-HTTP endpoint is under
  consideration; the tools are stateless, so hosting adds no custody.
- **Underlying schemes**: `iqa-org 1.3.1` (PyPI / npm / crates.io — four
  registries, byte-exact vectors, offline self-test).
- **Specification**: `draft-li-rttp-iqa-addressing` — Independent
  Submission, in review.

## Sister repositories

- **[iqa-org](https://github.com/Aicent-Stack/iqa-org)** — the reference
  implementation (addressing, envelope, verification).
- **[rttp](https://github.com/Aicent-Stack/rttp)** — the addressing
  scheme: design notes and open questions.
- **[Organization discussions](https://github.com/orgs/Aicent-Stack/discussions)** —
  start-here map and cross-repo threads.

---

## Public record

Everything this tool wraps is public and checkable — no asking us:

- **Landing page**: <https://iqa.org/MCP/>
- **Public record, dated**: <https://iqa.org/brief/>
- **Live demos — the audit chain this tool joins**:
  <https://iqa.org/demo/compare/> · <https://iqa.org/demo/delegation/>
- **Whitepaper**: <https://iqa.org/whitepaper/> (also at rttp.com/whitepaper)
- **Internet-Draft**: draft-li-rttp-iqa-addressing — Independent
  Submission, in review
- **The library this server wraps**: iqa-org 1.3.1 on PyPI — four
  registries, byte-exact vectors, offline self-test

---

## License

Apache-2.0 — © RTTP & IQA Organization
