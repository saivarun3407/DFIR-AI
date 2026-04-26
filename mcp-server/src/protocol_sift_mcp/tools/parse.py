"""Common parsing primitives (stubs)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..sandbox import assert_input_path


def magic_check(path: str) -> dict[str, str]:
    """TODO(W1): libmagic-based file type identification + signature verification."""
    p = assert_input_path(path)
    head = p.open("rb").read(16)
    return {"head_hex": head.hex(), "size": str(p.stat().st_size)}


def hex_inspect(path: str, offset: int, length: int) -> str:
    """Read a byte range and return hex. Bounded length to prevent OOM."""
    p = assert_input_path(path)
    if length > 1 << 16:
        raise ValueError("length > 64KiB; chunk your reads")
    with p.open("rb") as f:
        f.seek(offset)
        return f.read(length).hex()


def sqlite_query(db_path: str, query: str) -> list[dict[str, Any]]:
    """TODO(W2): Read-only SQLite query (SELECT only enforced)."""
    _ = assert_input_path(db_path)
    raise NotImplementedError("sqlite_query — implement W2")


def yara_scan(target_path: str, rule_path: str) -> list[dict[str, Any]]:
    """TODO(W2): YARA scan against memory dump or file."""
    _ = assert_input_path(target_path)
    _ = Path(rule_path)
    raise NotImplementedError("yara_scan — implement W2")
