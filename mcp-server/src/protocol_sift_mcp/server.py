"""MCP server entry point.

Wires the typed tool surface (evidence + finding + per-OS triage primitives)
to MCP's stdio protocol. Per-OS tools start as stubs with TODO markers; trust
primitives are real on day one because they gate everything else.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .tools import evidence as ev
from .tools import finding as fd
from .tools import windows as win

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
        Tool(
            name="win_registry_get",
            description=(
                "Read a Windows registry key from a hive (NTUSER.DAT, SOFTWARE, SYSTEM, "
                "SAM, USRCLASS.DAT). Returns {path, timestamp, hive_type, subkeys, values}. "
                "Each value includes raw_hex for evidence pinning. Empty registry_path = root."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "hive_path": {"type": "string", "description": "Path to hive under /input"},
                    "registry_path": {
                        "type": "string",
                        "description": (
                            "Backslash path under hive root, "
                            "e.g. Software\\\\Microsoft\\\\Windows"
                        ),
                        "default": "",
                    },
                },
                "required": ["hive_path"],
            },
        ),
        Tool(
            name="win_prefetch_parse",
            description=(
                "Parse a Windows .pf prefetch file. Returns executable_name, version, "
                "run_count, last_run_times (up to 8 for Win8+), volumes, files_accessed, "
                "directories. Prefetch is the strongest single-source proof of execution."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "prefetch_path": {"type": "string", "description": "Path to .pf under /input"},
                },
                "required": ["prefetch_path"],
            },
        ),
        Tool(
            name="win_evtx_query",
            description=(
                "Query a Windows Event Log (.evtx). Returns {record_id, eid, channel, "
                "time_created, computer, xml} per record. Filter by event_ids and time_range. "
                "xml is the raw record — cite as raw_excerpt in pins."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "log_path": {"type": "string", "description": "Path to .evtx under /input"},
                    "event_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Filter to these EIDs (e.g. [4624, 4625, 4648])",
                    },
                    "time_range": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "items": {"type": "string"},
                        "description": "(since_iso, until_iso) inclusive",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 1000,
                        "minimum": 1,
                        "maximum": 100000,
                    },
                },
                "required": ["log_path"],
            },
        ),
        Tool(
            name="win_lnk_parse",
            description=(
                "Parse a Windows shortcut (.lnk). Returns target, target MACB timestamps, "
                "drive serial + type, machine_id, working_dir, arguments, network_share. "
                "Use for File/Folder Opening + USB activity reconstruction."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "lnk_path": {"type": "string", "description": "Path to .lnk under /input"},
                },
                "required": ["lnk_path"],
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
                "ts": datetime.now(UTC).isoformat(),
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
    if name == "win_registry_get":
        result = win.win_registry_get(
            arguments["hive_path"],
            arguments.get("registry_path", ""),
        )
        return [TextContent(type="text", text=str(result))]
    if name == "win_prefetch_parse":
        result = win.win_prefetch_parse(arguments["prefetch_path"])
        return [TextContent(type="text", text=str(result))]
    if name == "win_evtx_query":
        time_range_arg = arguments.get("time_range")
        time_tuple = (
            (time_range_arg[0], time_range_arg[1])
            if time_range_arg and len(time_range_arg) == 2
            else None
        )
        result = win.win_evtx_query(
            arguments["log_path"],
            event_ids=arguments.get("event_ids"),
            time_range=time_tuple,
            limit=arguments.get("limit", 1000),
        )
        return [TextContent(type="text", text=str(result))]
    if name == "win_lnk_parse":
        result = win.win_lnk_parse(arguments["lnk_path"])
        return [TextContent(type="text", text=str(result))]
    raise ValueError(f"Unknown tool: {name}")


def main() -> None:
    import asyncio

    async def _run() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()
