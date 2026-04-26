---
name: evidence-pin
description: Citation discipline. Every claim must include a structured evidence pin (artifact + tool + offset/path + raw excerpt). MCP server rejects un-pinned findings — this skill teaches the format.
---

# Evidence Pin

Every finding MUST be backed by a pin. The MCP server's `finding_record` tool rejects records with empty `pins[]`. Do not try to bypass.

## Pin Schema

```json
{
  "artifact": "<filename or hive name>",
  "tool": "<exact MCP tool name that produced this>",
  "locator": {
    "type": "registry_path | file_offset | sql_row | log_line | memory_vad | evtx_record_id",
    "value": "<the specific locator value>"
  },
  "raw_excerpt": "<base64 or short hex/text snippet of the underlying bytes>",
  "captured_at": "<ISO-8601 timestamp>"
}
```

## Examples

### Registry
```json
{
  "artifact": "NTUSER.DAT",
  "tool": "win_registry_get",
  "locator": {
    "type": "registry_path",
    "value": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-...}\\Count\\HRZR_PGYFRFFvbaA"
  },
  "raw_excerpt": "01000000020000005c530000...",
  "captured_at": "2026-04-25T22:14:03Z"
}
```

### Memory VAD
```json
{
  "artifact": "memory.dmp",
  "tool": "windows.malfind",
  "locator": {
    "type": "memory_vad",
    "value": "pid=4216 vad_start=0x7ff812340000 vad_end=0x7ff812350000"
  },
  "raw_excerpt": "4d5a90000300000004000000ffff0000",
  "captured_at": "2026-04-25T22:14:09Z"
}
```

### EVTX
```json
{
  "artifact": "Security.evtx",
  "tool": "win_evtx_query",
  "locator": {
    "type": "evtx_record_id",
    "value": "EID=4624, RecordID=18342, Channel=Security"
  },
  "raw_excerpt": "<EventData>...</EventData>",
  "captured_at": "2026-04-25T22:14:15Z"
}
```

## Confidence Pairing

Each pin contributes to a finding's confidence. Confidence rules:

| # of Pins | Independent Sources | Confidence |
|---|---|---|
| 1 | 1 | `inferred` |
| ≥2 | ≥2 distinct artifacts | `confirmed` |
| ≥1 | suggestive but not definitive | `uncertain` |
| 0 | — | INVALID — MCP rejects |

"Independent" means the pin sources don't derive from each other. Two registry keys in the same hive = ONE source. Registry + Prefetch + EVTX = THREE sources.

## What NOT To Do

- Do NOT cite a tool you didn't actually call this session
- Do NOT fabricate offsets — the MCP server's `verify_excerpt` runs server-side and will reject mismatches
- Do NOT pin to `/output` paths — only `/input` artifacts are valid sources
