"""MCP server entry point.

Wires the typed tool surface (evidence + finding + per-OS triage primitives)
to MCP's stdio protocol. Per-OS tools start as stubs with TODO markers; trust
primitives are real on day one because they gate everything else.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .tools import evidence as ev
from .tools import finding as fd

OUTPUT_PATH = Path(os.environ.get("OUTPUT_PATH", "/output"))
CHAIN_PATH = OUTPUT_PATH / "chain-of-custody.jsonl"
FINDINGS_PATH = OUTPUT_PATH / "findings.json"

server: Server = Server("protocol-sift")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="hash",
            description="Compute sha256 + sha1 of an evidence file. Returns {sha256, sha1, size}.",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        ),
        Tool(
            name="chain_append",
            description="Append a chain-of-custody entry. Use sparingly; most events are auto-logged by hooks.",
            inputSchema={
                "type": "object",
                "properties": {
                    "event": {"type": "string"},
                    "data": {"type": "object"},
                },
                "required": ["event", "data"],
            },
        ),
        Tool(
            name="chain_verify",
            description="Recompute every chain hash. Returns {ok, problems}.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="chain_acknowledge_gap",
            description="Record an explicit 'I don't know' with scope + reason. Counts positively in accuracy report.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scope": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["scope", "reason"],
            },
        ),
        Tool(
            name="finding_record",
            description="Register a finding. REJECTS if pins[] is empty — use chain_acknowledge_gap instead.",
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "claim": {"type": "string"},
                    "confidence": {
                        "type": "string",
                        "enum": ["confirmed", "inferred", "uncertain", "unknown"],
                    },
                    "pins": {"type": "array", "minItems": 1},
                    "mitre_attck": {"type": "array", "items": {"type": "string"}},
                    "related_findings": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["finding_id", "claim", "confidence", "pins"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "hash":
        digest = ev.hash_file(Path(arguments["path"]))
        return [TextContent(type="text", text=str(digest))]
    if name == "chain_append":
        entry = ev.chain_append(
            CHAIN_PATH,
            event=arguments["event"],
            data=arguments["data"],
        )
        return [TextContent(type="text", text=str(entry))]
    if name == "chain_verify":
        ok, problems = ev.chain_verify(CHAIN_PATH)
        return [
            TextContent(
                type="text",
                text=f"ok={ok} problems={problems}",
            )
        ]
    if name == "chain_acknowledge_gap":
        entry = ev.chain_append(
            CHAIN_PATH,
            event="gap_acknowledged",
            data={
                "scope": arguments["scope"],
                "reason": arguments["reason"],
                "ts": datetime.now(timezone.utc).isoformat(),
            },
        )
        return [TextContent(type="text", text=str(entry))]
    if name == "finding_record":
        record = fd.finding_record(FINDINGS_PATH, arguments)
        ev.chain_append(
            CHAIN_PATH,
            event="finding_recorded",
            data={"finding_id": record["finding_id"]},
        )
        return [TextContent(type="text", text=str(record))]
    raise ValueError(f"Unknown tool: {name}")


def main() -> None:
    import asyncio

    async def _run() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()
