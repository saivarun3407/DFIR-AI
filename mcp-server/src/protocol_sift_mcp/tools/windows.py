"""Windows DFIR primitives (stubs).

Each function is a typed forensic primitive. No shell exec, no destructive ops.
TODO markers indicate W2 implementation targets.
"""

from __future__ import annotations

from typing import Any

from ..sandbox import assert_input_path


def win_registry_get(hive_path: str, registry_path: str) -> dict[str, Any]:
    """TODO(W2): Use python-registry to read a registry value with type."""
    _ = assert_input_path(hive_path)
    raise NotImplementedError("win_registry_get — implement W2")


def win_evtx_query(
    log_path: str,
    *,
    event_ids: list[int] | None = None,
    time_range: tuple[str, str] | None = None,
) -> list[dict[str, Any]]:
    """TODO(W2): Use python-evtx to filter records by EID and time."""
    _ = assert_input_path(log_path)
    raise NotImplementedError("win_evtx_query — implement W2")


def win_prefetch_parse(prefetch_path: str) -> dict[str, Any]:
    """TODO(W2): Parse a .pf file — return last 8 exec times, run count, file handles."""
    _ = assert_input_path(prefetch_path)
    raise NotImplementedError("win_prefetch_parse — implement W2")


def win_lnk_parse(lnk_path: str) -> dict[str, Any]:
    """TODO(W2): Parse LNK — target MACB, volume info, network share, system name."""
    _ = assert_input_path(lnk_path)
    raise NotImplementedError("win_lnk_parse — implement W2")


def win_shellbag_parse(hive_path: str) -> list[dict[str, Any]]:
    """TODO(W2): ShellBags from USRCLASS.DAT or NTUSER.DAT."""
    _ = assert_input_path(hive_path)
    raise NotImplementedError("win_shellbag_parse — implement W2")


def win_recyclebin_parse(recycle_dir: str) -> list[dict[str, Any]]:
    """TODO(W2): Parse $I###### and $R###### pairs."""
    _ = assert_input_path(recycle_dir)
    raise NotImplementedError("win_recyclebin_parse — implement W2")


def win_ese_query(db_path: str, table: str, query: str) -> list[dict[str, Any]]:
    """TODO(W2): ESE database query (SRUDB.dat, Windows.edb, WebCacheV01.dat)."""
    _ = assert_input_path(db_path)
    raise NotImplementedError("win_ese_query — implement W2")
