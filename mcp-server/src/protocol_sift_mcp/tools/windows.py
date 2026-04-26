"""Windows DFIR primitives.

Each function is a typed forensic primitive. No shell exec, no destructive ops.
"""

from __future__ import annotations

from typing import Any

from ..sandbox import assert_input_path


class RegistryToolError(Exception):
    """Wraps any failure surfaced from python-registry into a single boundary error.

    Lets the agent treat 'key missing' the same as 'hive corrupted' at the API
    layer, while preserving the original cause for the chain log.
    """


def _import_registry() -> Any:
    """Lazy-import python-registry so module load works without [forensics] extra installed.

    Tests stub this via sys.modules patching. Raises a clear error if the
    optional dep is missing on a real run.
    """
    try:
        from Registry import Registry as _Registry
    except ImportError as exc:
        raise RegistryToolError(
            "python-registry not installed. "
            "Install with: pip install -e 'mcp-server[forensics]'"
        ) from exc
    return _Registry


def win_registry_get(hive_path: str, registry_path: str = "") -> dict[str, Any]:
    """Read a registry key from a Windows hive file.

    Args:
        hive_path: Path inside the evidence sandbox to the hive file
            (NTUSER.DAT, SOFTWARE, SYSTEM, SAM, USRCLASS.DAT, etc.)
        registry_path: Backslash-delimited path under the hive root.
            Empty string returns the root key.

    Returns:
        dict with: path, timestamp (ISO), hive_type, subkeys (names), values
        (each: name, value_type, value, raw_hex). raw_hex enables evidence
        pinning — the agent cites this hex in finding pins.

    Raises:
        SandboxViolation if hive_path escapes /input.
        RegistryToolError on any python-registry failure (key not found,
        corrupted hive, missing optional dep).
    """
    p = assert_input_path(hive_path)
    _Registry = _import_registry()

    try:
        reg = _Registry.Registry(str(p))
    except Exception as exc:
        raise RegistryToolError(f"Failed to open hive {p}: {exc}") from exc

    try:
        key = reg.open(registry_path) if registry_path else reg.root()
    except Exception as exc:
        raise RegistryToolError(
            f"Registry path not found: {registry_path!r} in {p.name}"
        ) from exc

    values: list[dict[str, Any]] = []
    for v in key.values():
        try:
            decoded = v.value()
        except Exception:
            decoded = None
        try:
            raw = v.raw_data() if hasattr(v, "raw_data") else b""
            raw_hex = raw.hex() if isinstance(raw, (bytes, bytearray)) else ""
        except Exception:
            raw_hex = ""
        try:
            type_str = v.value_type_str()
        except Exception:
            type_str = "UNKNOWN"
        values.append(
            {
                "name": v.name() or "(default)",
                "value_type": type_str,
                "value": _coerce_value(decoded),
                "raw_hex": raw_hex,
            }
        )

    subkey_names: list[str] = []
    for sk in key.subkeys():
        try:
            subkey_names.append(sk.name())
        except Exception:  # noqa: S112 — skip individual corrupted subkey, surface rest
            continue

    timestamp = None
    try:
        ts = key.timestamp()
        if ts is not None:
            timestamp = ts.isoformat()
    except Exception:
        timestamp = None

    hive_type = None
    try:
        hive_type = str(reg.hive_type()) if hasattr(reg, "hive_type") else None
    except Exception:
        hive_type = None

    return {
        "path": _safe_path(key, registry_path),
        "timestamp": timestamp,
        "hive_type": hive_type,
        "subkeys": subkey_names,
        "values": values,
    }


def _coerce_value(v: Any) -> Any:
    """Reduce decoded values to JSON-serializable forms. Bytes → hex string."""
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, list):
        return [_coerce_value(x) for x in v]
    return v


def _safe_path(key: Any, fallback: str) -> str:
    try:
        return key.path()
    except Exception:
        return fallback or "(root)"


class PrefetchToolError(Exception):
    """Boundary error for windowsprefetch failures."""


class EvtxToolError(Exception):
    """Boundary error for python-evtx failures."""


class LnkToolError(Exception):
    """Boundary error for pylnk3 failures."""


def _import_prefetch() -> Any:
    try:
        from windowsprefetch import Prefetch
    except ImportError as exc:
        raise PrefetchToolError(
            "windowsprefetch not installed. "
            "Install with: pip install -e 'mcp-server[forensics]'"
        ) from exc
    return Prefetch


def _import_evtx() -> Any:
    try:
        import Evtx.Evtx as evtx
    except ImportError as exc:
        raise EvtxToolError(
            "python-evtx not installed. "
            "Install with: pip install -e 'mcp-server[forensics]'"
        ) from exc
    return evtx


def _import_lnk() -> Any:
    try:
        import pylnk3
    except ImportError as exc:
        raise LnkToolError(
            "pylnk3 not installed. "
            "Install with: pip install -e 'mcp-server[forensics]'"
        ) from exc
    return pylnk3


def win_prefetch_parse(prefetch_path: str) -> dict[str, Any]:
    """Parse a Windows .pf prefetch file.

    Returns: executable_name, run_count, last_run_times (up to 8 for Win8+),
    version (17/23/26/30=XP/7/8/10), volumes, files_accessed, directories.
    Win10 prefetch is XPRESS-Huffman compressed; the underlying library
    handles decompression. raw_excerpt for pins should cite the .pf path
    and a specific timestamp index.
    """
    p = assert_input_path(prefetch_path)
    Prefetch = _import_prefetch()
    try:
        pf = Prefetch(str(p))
    except Exception as exc:
        raise PrefetchToolError(f"Failed to parse prefetch {p.name}: {exc}") from exc

    last_run_times: list[str] = []
    raw_lrt = getattr(pf, "lastRunTime", None) or getattr(pf, "lastRunTimes", None)
    if raw_lrt is not None:
        items = raw_lrt if isinstance(raw_lrt, list) else [raw_lrt]
        for ts in items:
            try:
                last_run_times.append(ts.isoformat())
            except Exception:  # noqa: S112 — skip a single malformed timestamp
                continue

    return {
        "path": str(p),
        "executable_name": getattr(pf, "executableName", None),
        "version": getattr(pf, "version", None),
        "run_count": getattr(pf, "runCount", None),
        "last_run_times": last_run_times,
        "volumes": list(getattr(pf, "volumesInformation", []) or []),
        "files_accessed": list(getattr(pf, "filesAccessed", []) or []),
        "directories": list(getattr(pf, "directoryStrings", []) or []),
    }


def win_evtx_query(
    log_path: str,
    *,
    event_ids: list[int] | None = None,
    time_range: tuple[str, str] | None = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Query a Windows Event Log (.evtx) file.

    Args:
        log_path: path under /input to .evtx file
        event_ids: optional list of EID filters (e.g. [4624, 4625, 4648])
        time_range: optional (since_iso, until_iso) tuple, inclusive
        limit: max records returned (default 1000)

    Returns: list of {record_id, eid, channel, time_created, computer, xml}.
    XML field is the raw record XML — agent cites it in pin raw_excerpt.
    """
    p = assert_input_path(log_path)
    evtx = _import_evtx()

    eid_filter = set(event_ids) if event_ids else None
    since_iso, until_iso = time_range if time_range else (None, None)

    try:
        log = evtx.Evtx(str(p))
    except Exception as exc:
        raise EvtxToolError(f"Failed to open evtx {p.name}: {exc}") from exc

    results: list[dict[str, Any]] = []
    try:
        with log as opened:
            for record in opened.records():
                if len(results) >= limit:
                    break
                xml = record.xml()
                eid = _parse_evtx_eid(xml)
                if eid_filter and eid not in eid_filter:
                    continue
                ts = _parse_evtx_time(xml)
                if since_iso and ts and ts < since_iso:
                    continue
                if until_iso and ts and ts > until_iso:
                    continue
                results.append(
                    {
                        "record_id": _parse_evtx_record_id(xml),
                        "eid": eid,
                        "channel": _parse_evtx_channel(xml),
                        "time_created": ts,
                        "computer": _parse_evtx_computer(xml),
                        "xml": xml,
                    }
                )
    except Exception as exc:
        raise EvtxToolError(f"Failed to iterate evtx {p.name}: {exc}") from exc
    return results


def win_lnk_parse(lnk_path: str) -> dict[str, Any]:
    """Parse a Windows shortcut (.lnk) file.

    Returns: target path, target MACB timestamps, volume info, network share,
    working directory, command-line arguments, original file size,
    machine name (system that created the shortcut). Useful for tracking
    USB activity, file/folder opens, and timeline reconstruction.
    """
    p = assert_input_path(lnk_path)
    pylnk3 = _import_lnk()
    try:
        with open(str(p), "rb") as fh:  # noqa: PTH123 — pylnk3 expects file handle
            link = pylnk3.parse(fh)
    except Exception as exc:
        raise LnkToolError(f"Failed to parse lnk {p.name}: {exc}") from exc

    return {
        "path": str(p),
        "target": getattr(link, "path", None) or getattr(link, "lnk_path", None),
        "working_dir": getattr(link, "working_dir", None),
        "arguments": getattr(link, "arguments", None),
        "description": getattr(link, "description", None),
        "machine_id": getattr(link, "machine_id", None),
        "drive_serial": getattr(link, "drive_serial", None),
        "drive_type": str(getattr(link, "drive_type", None)) if hasattr(link, "drive_type") else None,
        "creation_time": _to_iso(getattr(link, "creation_time", None)),
        "modification_time": _to_iso(getattr(link, "modification_time", None)),
        "access_time": _to_iso(getattr(link, "access_time", None)),
        "file_size": getattr(link, "file_size", None),
        "network_share": getattr(link, "network_share_name", None),
    }


def _to_iso(v: Any) -> str | None:
    if v is None:
        return None
    try:
        return v.isoformat()
    except Exception:
        return str(v)


def _parse_evtx_eid(xml: str) -> int | None:
    import re

    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
    return int(m.group(1)) if m else None


def _parse_evtx_record_id(xml: str) -> str | None:
    import re

    m = re.search(r'EventRecordID="?(\d+)"?', xml) or re.search(
        r"<EventRecordID>(\d+)</EventRecordID>", xml
    )
    return m.group(1) if m else None


def _parse_evtx_channel(xml: str) -> str | None:
    import re

    m = re.search(r"<Channel>([^<]+)</Channel>", xml)
    return m.group(1) if m else None


def _parse_evtx_time(xml: str) -> str | None:
    import re

    m = re.search(r'SystemTime="([^"]+)"', xml)
    return m.group(1) if m else None


def _parse_evtx_computer(xml: str) -> str | None:
    import re

    m = re.search(r"<Computer>([^<]+)</Computer>", xml)
    return m.group(1) if m else None


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
