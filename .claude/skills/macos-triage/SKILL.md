---
name: macos-triage
description: macOS DFIR artifact triage. Use when evidence is macOS (APFS image, plist, Unified Logs tracev3, KnowledgeC, Spotlight). Encodes FOR518 + DFIR Cheat Sheet APFS section.
---

# macOS Triage

## Filesystem (APFS)

Reference: SANS DFIR Cheat Sheet pp. 15-17.

- **Container superblock** — first to parse; gives volume layout, snapshot list, encryption state
- **Volume superblock** — per-volume metadata, root tree OID
- **B-tree nodes** — file records, extent records, inode records
- **Object headers** — every object has `obj_oid`, `obj_xid`, `obj_type`, `obj_subtype`. Verify checksums.
- **Snapshots** — APFS snapshots may contain pre-attack state. Always enumerate.

## User Activity

- **KnowledgeC.db** — `~/Library/Application Support/Knowledge/knowledgeC.db` (SQLite). App usage, screen time, Bluetooth, focus, locations.
- **Unified Logs** — `/var/db/diagnostics/*.tracev3`. Use `log show --archive` or `log collect`. Subsystems: `com.apple.*`. Predicate filters required for tractable size.
- **Spotlight** — `.Spotlight-V100` (per-volume). Metadata index. Can reveal deleted files referenced.
- **QuarantineEventsV2** — `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`. SQLite. Files downloaded, source URL, sender, timestamp.
- **Shell history** — `~/.bash_history`, `~/.zsh_history` (also session-isolated `~/.zsh_sessions/`)
- **Recent items** — `~/Library/Preferences/com.apple.recentitems.plist`

## iOS Apps (if backup ingested)

DFIR Cheat Sheet pp. 22-33 documents 40+ apps with exact DB paths. Examples:
- Signal: `~/Library/Application Support/Signal/sql/db.sqlite` (encrypted; key in Keychain)
- WhatsApp: `~/Library/Mobile Documents/.../ChatStorage.sqlite`
- Telegram: `Documents/postbox/.../db_sqlite`
- Slack: `~/Library/Application Support/Slack/Cache`

Refer to source booklet for full path table.

## MCP Tools

- `mcp__protocol_sift__mac_apfs_inspect(image_path)` → container/volume/snapshot tree
- `mcp__protocol_sift__mac_plist_get(path, key_path)` → typed value
- `mcp__protocol_sift__mac_tracev3_query(archive, predicate, time_range)` → log entries
- `mcp__protocol_sift__mac_knowledgec_query(db, table, query)` → activity rows
- `mcp__protocol_sift__mac_spotlight_query(volume, query)` → metadata results

## Pin Format

```json
{
  "artifact": "knowledgeC.db",
  "tool": "mac_knowledgec_query",
  "table": "ZOBJECT",
  "row_id": 12345,
  "raw_excerpt": "..."
}
```

## Cross-Confirmation Rules

- App execution: KnowledgeC `/app/usage` + Unified Log `com.apple.launchservices` = `confirmed`
- File download: QuarantineEventsV2 + browser history = `confirmed`. QuarantineEventsV2 alone = `inferred`.
