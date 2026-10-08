# -*- coding: utf-8 -*-
"""MCP protocol-level test for the iqa-mcp server (stdio transport).

Seven assertions:
  1. list_tools            -> the four tools, with descriptions
  2. derive_route_shard    -> matches the live-demo shard 5c378581...
  3. published_vector      -> returns the documented parameters
  4. parse_envelope        -> structural decode [PASS], standing Radiant
  5. verify_envelope       -> [PASS] byte for byte, offline
  6. verify_envelope       -> tampered byte -> REJECT (fail-closed)
  7. parse_envelope        -> malformed hex -> REJECT, never a partial
"""

import asyncio
import json
import os
import shutil
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _resolve_params() -> StdioServerParameters:
    """Locate the iqa-mcp server without assuming a checkout layout.

    Order: IQA_MCP_CMD override -> ./server.py (source checkout) ->
    the installed `iqa-mcp` console script (PyPI layout, venv or PATH).
    """
    override = os.environ.get("IQA_MCP_CMD")
    if override:
        return StdioServerParameters(command=override)
    if os.path.exists("server.py"):
        return StdioServerParameters(command=sys.executable,
                                     args=["server.py"])
    here = os.path.dirname(sys.executable)
    for cand in (os.path.join(here, "iqa-mcp.exe"),
                 os.path.join(here, "iqa-mcp")):
        if os.path.isfile(cand):
            return StdioServerParameters(command=cand)
    exe = shutil.which("iqa-mcp")
    if exe:
        return StdioServerParameters(command=exe)
    raise SystemExit(
        "cannot locate the iqa-mcp server: no ./server.py here and no "
        "iqa-mcp console script on PATH — run from the source checkout "
        "or `pip install iqa-mcp`"
    )


PARAMS = _resolve_params()


async def main() -> int:
    async with stdio_client(PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            ok_count = 0

            # 1. list_tools
            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            assert names == ["derive_route_shard", "parse_envelope",
                             "published_vector", "verify_envelope"], names
            print("[PASS] 1 · list_tools ->", names)
            ok_count += 1

            # 2. derive_route_shard -- must match the live-demo shard
            r = await session.call_tool("derive_route_shard",
                                        {"authority": "3f9a1b2c.gateway.iqa"})
            shard = r.content[0].text
            assert shard == "5c378581f92754d0bc88adaed84b7c5a", shard
            print("[PASS] 2 · derive_route_shard ->", shard)
            ok_count += 1

            # 3. published_vector
            r = await session.call_tool("published_vector", {})
            vec = json.loads(r.content[0].text)
            assert vec["organ"] == "ORG-TEST" and vec["standing"] == "radiant"
            assert len(vec["frame_hex"]) == 256
            print("[PASS] 3 · published_vector ->", vec["authority"])
            ok_count += 1

            # 4. parse_envelope -- structural decode, no key needed
            r = await session.call_tool("parse_envelope", {"envelope_hex": vec["frame_hex"]})
            parsed = json.loads(r.content[0].text)
            assert parsed["ok"] and parsed["frame"]["standing_name"] == "radiant"
            assert parsed["frame"]["organ"] == "ORG-TEST"
            assert parsed["frame"]["intent_shard"] == "557c8154d3780cb78cc5fa1bd72b331c"
            print("[PASS] 4 · parse_envelope -> standing", parsed["frame"]["standing_name"])
            ok_count += 1

            # 5. verify_envelope -- [PASS] byte for byte, offline
            r = await session.call_tool("verify_envelope",
                                        {"envelope_hex": vec["frame_hex"],
                                         "organ_key": vec["organ_key"],
                                         "check_lease": False})
            verdict = json.loads(r.content[0].text)
            assert verdict["ok"] and verdict["frame"]["standing_name"] == "radiant"
            assert verdict["frame"]["nonce"] == 1
            print("[PASS] 5 · verify_envelope -> [PASS] Radiant · nonce 1")
            ok_count += 1

            # 6. tamper -- flip one bit of the standing byte -> REJECT
            raw = bytearray(bytes.fromhex(vec["frame_hex"]))
            raw[80] = 3  # Genesis
            r = await session.call_tool("verify_envelope",
                                        {"envelope_hex": raw.hex(),
                                         "organ_key": vec["organ_key"],
                                         "check_lease": False})
            verdict = json.loads(r.content[0].text)
            assert not verdict["ok"] and "HMAC mismatch" in verdict["reject"]
            print("[PASS] 6 · tampered frame -> REJECT (", verdict["reject"], ")")
            ok_count += 1

            # 7. malformed input -- fail closed, never a partial
            r = await session.call_tool("parse_envelope", {"envelope_hex": "zz"})
            parsed = json.loads(r.content[0].text)
            assert not parsed["ok"] and "invalid hex" in parsed["reject"]
            print("[PASS] 7 · malformed hex -> REJECT (", parsed["reject"], ")")
            ok_count += 1

    print("ALL %d/7 PASS" % ok_count)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
