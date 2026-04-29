"""macOS DFIR primitives.

mac_plist_get + mac_knowledgec_query use Python stdlib (plistlib, sqlite3) so
they work without the [forensics] extra. Heavier APFS / tracev3 / Spotlight
parsers stay stubbed for W3 mid-week (need apfs-fuse / libtracev3).
"""

from __future__ import annotations

import plistlib
import sqlite3
from typing import Any

from ..sandbox import assert_input_path


class PlistToolError(Exception):
    """Boundary error for plist parse failures."""


class KnowledgeCToolError(Exception):
    """Boundary error for knowledgeC.db queries."""


def mac_plist_get(plist_path: str, key_path: str = "") -> dict[str, Any]:
    """Parse a macOS property list (XML or binary).

    Args:
        plist_path: path under /input to .plist file
        key_path: slash-separated traversal (e.g. ``"NSRecentDocuments/0/URL"`` or
            ``"Apps/com.apple.dock/RecentDocs/0"``). Slash is used because bundle
            identifiers contain dots. Empty string returns full root.

    Returns:
        {path, format ("xml"|"binary"|"unknown"), root_keys, value, value_type, size}
        - root_keys: top-level keys when root is a dict (else empty list)
        - value: traversed value at key_path, JSON-coerced (bytes → hex)
        - value_type: Python type name of the value pre-coercion

    Raises:
        SandboxViolation if path escapes /input.
        PlistToolError on parse or traversal failure.
    """
    p = assert_input_path(plist_path)
    try:
        with p.open("rb") as f:
            head = f.read(256)
            f.seek(0)
            data = plistlib.load(f)
    except plistlib.InvalidFileException as exc:
        raise PlistToolError(f"Not a valid plist: {p.name}") from exc
    except Exception as exc:
        raise PlistToolError(f"Failed to parse plist {p.name}: {exc}") from exc

    if head.startswith(b"bplist00"):
        fmt = "binary"
    elif b"<?xml" in head or b"<plist" in head:
        fmt = "xml"
    else:
        fmt = "unknown"

    root_keys: list[str] = []
    if isinstance(data, dict):
        root_keys = list(data.keys())

    value: Any = data
    if key_path:
        try:
            value = _traverse(data, key_path)
        except (KeyError, IndexError, TypeError) as exc:
            raise PlistToolError(f"Key path not found: {key_path!r}") from exc

    return {
        "path": str(p),
        "format": fmt,
        "size": p.stat().st_size,
        "root_keys": root_keys,
        "key_path": key_path,
        "value_type": type(value).__name__,
        "value": _coerce(value),
    }


def mac_knowledgec_query(
    db_path: str,
    *,
    sql: str | None = None,
    table: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query macOS knowledgeC.db (app usage, screen time, focus, locations).

    Located at ``~/Library/Application Support/Knowledge/knowledgeC.db``.
    Read-only SQLite. Either pass a custom ``sql`` string (SELECT only) or
    a ``table`` name to dump rows from.

    Returns: list of row dicts. Bytes coerced to hex.

    Raises:
        KnowledgeCToolError on connection or query failure.
        ValueError if both/neither of sql and table supplied, or if sql
        contains a non-SELECT statement.
    """
    p = assert_input_path(db_path)
    if (sql is None) == (table is None):
        raise ValueError("Provide exactly one of sql or table")

    if sql is not None:
        stripped = sql.strip().lower()
        if not stripped.startswith("select") and not stripped.startswith("with"):
            raise ValueError("Only SELECT / WITH queries allowed")
    else:
        if not _is_safe_table_name(table or ""):
            raise ValueError(f"Invalid table name: {table!r}")
        # Table name validated by _is_safe_table_name (alphanumeric + underscore only).
        sql = f"SELECT * FROM {table} LIMIT ?"  # noqa: S608 — table name allowlisted above

    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error as exc:
        raise KnowledgeCToolError(f"Failed to open {p.name}: {exc}") from exc

    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            params: tuple[Any, ...] = (limit,) if table is not None else ()
            cur.execute(sql, params)
            rows = cur.fetchmany(limit)
        except sqlite3.Error as exc:
            raise KnowledgeCToolError(f"Query failed: {exc}") from exc
        return [{k: _coerce(row[k]) for k in row.keys()} for row in rows]
    finally:
        conn.close()


def mac_apfs_inspect(image_path: str) -> dict[str, Any]:
    """TODO(W3): apfs-fuse + custom parser for container/volume/snapshot tree."""
    _ = assert_input_path(image_path)
    raise NotImplementedError("mac_apfs_inspect — implement W3")


def mac_tracev3_query(
    archive_path: str, predicate: str, time_range: tuple[str, str] | None = None
) -> list[dict[str, Any]]:
    """TODO(W3): Unified Logs query. May require macFUSE for archive mount."""
    _ = assert_input_path(archive_path)
    _ = predicate
    _ = time_range
    raise NotImplementedError("mac_tracev3_query — implement W3")


def mac_spotlight_query(volume_path: str, query: str) -> list[dict[str, Any]]:
    """TODO(W3): .Spotlight-V100 metadata index query."""
    _ = assert_input_path(volume_path)
    _ = query
    raise NotImplementedError("mac_spotlight_query — implement W3")


# ─── helpers ─────────────────────────────────────────────────────────────────


def _traverse(data: Any, key_path: str) -> Any:
    """Walk a slash-separated path through a plist tree (dicts + lists).

    Slash chosen because bundle IDs (com.apple.dock) contain dots — using
    dot as separator would break the most common plist key shape.
    """
    cur = data
    for part in key_path.split("/"):
        if not part:
            continue
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise TypeError(
                f"Cannot traverse {part!r} on non-container at {type(cur).__name__}"
            )
    return cur


def _coerce(v: Any) -> Any:
    """Reduce plist/SQLite values to JSON-safe form. Bytes → hex string."""
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, dict):
        return {str(k): _coerce(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_coerce(x) for x in v]
    if hasattr(v, "isoformat"):
        try:
            return v.isoformat()
        except Exception:  # noqa: S110 — fall through to repr if isoformat impl missing/broken
            pass
    return v


def _is_safe_table_name(name: str) -> bool:
    return bool(name) and name.replace("_", "").isalnum()
