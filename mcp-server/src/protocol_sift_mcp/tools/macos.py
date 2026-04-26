"""macOS DFIR primitives (stubs). TODO(W3) implementation."""

from __future__ import annotations

from typing import Any

from ..sandbox import assert_input_path


def mac_apfs_inspect(image_path: str) -> dict[str, Any]:
    """TODO(W3): apfs-fuse + custom parser for container/volume/snapshot tree."""
    _ = assert_input_path(image_path)
    raise NotImplementedError("mac_apfs_inspect — implement W3")


def mac_plist_get(plist_path: str, key_path: str) -> Any:
    """TODO(W3): plistlib + key-path traversal."""
    _ = assert_input_path(plist_path)
    raise NotImplementedError("mac_plist_get — implement W3")


def mac_tracev3_query(
    archive_path: str, predicate: str, time_range: tuple[str, str] | None = None
) -> list[dict[str, Any]]:
    """TODO(W3): Unified Logs query. May require macFUSE for archive mount."""
    _ = assert_input_path(archive_path)
    raise NotImplementedError("mac_tracev3_query — implement W3")


def mac_knowledgec_query(db_path: str, table: str, query: str) -> list[dict[str, Any]]:
    """TODO(W3): SQLite query against knowledgeC.db with stream type decoding."""
    _ = assert_input_path(db_path)
    raise NotImplementedError("mac_knowledgec_query — implement W3")


def mac_spotlight_query(volume_path: str, query: str) -> list[dict[str, Any]]:
    """TODO(W3): .Spotlight-V100 metadata index query."""
    _ = assert_input_path(volume_path)
    raise NotImplementedError("mac_spotlight_query — implement W3")
