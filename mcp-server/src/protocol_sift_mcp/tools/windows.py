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
