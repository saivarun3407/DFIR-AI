"""Windows MCP tool tests. Mocks python-registry so CI runs with core deps only.

Real-hive integration tests will live behind an `integration` marker once we
have a fixture hive; for now the unit tests prove the wrapper logic — sandbox
gating, error translation, value coercion, and structured return shape.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from protocol_sift_mcp import sandbox
from protocol_sift_mcp.tools import windows as win


def _fake_value(name: str, type_str: str, value: object, raw: bytes) -> MagicMock:
    v = MagicMock()
    v.name.return_value = name
    v.value_type_str.return_value = type_str
    v.value.return_value = value
    v.raw_data.return_value = raw
    return v


def _fake_subkey(name: str) -> MagicMock:
    s = MagicMock()
    s.name.return_value = name
    return s


def _fake_key(
    path: str,
    timestamp: datetime | None,
    values: list[MagicMock],
    subkeys: list[MagicMock],
) -> MagicMock:
    k = MagicMock()
    k.path.return_value = path
    k.timestamp.return_value = timestamp
    k.values.return_value = values
    k.subkeys.return_value = subkeys
    return k


def _install_fake_registry(monkeypatch: pytest.MonkeyPatch, reg_obj: MagicMock) -> None:
    """Inject a stand-in for `from Registry import Registry as _Registry`."""
    fake_inner = SimpleNamespace(Registry=MagicMock(return_value=reg_obj))
    fake_pkg = SimpleNamespace(Registry=fake_inner)
    monkeypatch.setitem(sys.modules, "Registry", fake_pkg)
    monkeypatch.setitem(sys.modules, "Registry.Registry", fake_inner)


def _evidence_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "NTUSER.DAT") -> Path:
    input_dir = tmp_path / "input"
    input_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "INPUT_ROOT", input_dir.resolve())
    f = input_dir / name
    f.write_bytes(b"\x00" * 16)
    return f


def test_win_registry_get_returns_structured_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hive = _evidence_file(tmp_path, monkeypatch)

    ts = datetime(2026, 4, 25, 23, 0, tzinfo=UTC)
    key = _fake_key(
        path=r"Software\Microsoft\Windows\CurrentVersion",
        timestamp=ts,
        values=[
            _fake_value("ProgramFilesDir", "REG_SZ", r"C:\Program Files", b"C:\\Program Files"),
            _fake_value("FontCacheVersion", "REG_DWORD", 0x35, b"\x35\x00\x00\x00"),
        ],
        subkeys=[_fake_subkey("Run"), _fake_subkey("RunOnce")],
    )
    reg = MagicMock()
    reg.open.return_value = key
    reg.hive_type.return_value = "SOFTWARE"
    _install_fake_registry(monkeypatch, reg)

    result = win.win_registry_get(str(hive), r"Software\Microsoft\Windows\CurrentVersion")

    assert result["path"] == r"Software\Microsoft\Windows\CurrentVersion"
    assert result["timestamp"] == "2026-04-25T23:00:00+00:00"
    assert result["hive_type"] == "SOFTWARE"
    assert result["subkeys"] == ["Run", "RunOnce"]
    assert len(result["values"]) == 2
    assert result["values"][0]["name"] == "ProgramFilesDir"
    assert result["values"][0]["value_type"] == "REG_SZ"
    assert result["values"][0]["raw_hex"] == b"C:\\Program Files".hex()


def test_win_registry_get_root_when_path_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hive = _evidence_file(tmp_path, monkeypatch)
    root = _fake_key(path="(root)", timestamp=None, values=[], subkeys=[_fake_subkey("Software")])
    reg = MagicMock()
    reg.root.return_value = root
    reg.hive_type.return_value = "NTUSER"
    _install_fake_registry(monkeypatch, reg)

    result = win.win_registry_get(str(hive))

    reg.root.assert_called_once()
    reg.open.assert_not_called()
    assert result["subkeys"] == ["Software"]


def test_win_registry_get_coerces_bytes_to_hex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hive = _evidence_file(tmp_path, monkeypatch)
    key = _fake_key(
        path="key",
        timestamp=None,
        values=[_fake_value("blob", "REG_BINARY", b"\xde\xad\xbe\xef", b"\xde\xad\xbe\xef")],
        subkeys=[],
    )
    reg = MagicMock()
    reg.open.return_value = key
    _install_fake_registry(monkeypatch, reg)

    result = win.win_registry_get(str(hive), "key")
    assert result["values"][0]["value"] == "deadbeef"
    assert result["values"][0]["raw_hex"] == "deadbeef"


def test_win_registry_get_invalid_path_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hive = _evidence_file(tmp_path, monkeypatch)
    reg = MagicMock()
    reg.open.side_effect = KeyError("Software\\Bogus")
    _install_fake_registry(monkeypatch, reg)

    with pytest.raises(win.RegistryToolError) as excinfo:
        win.win_registry_get(str(hive), r"Software\Bogus")
    assert "Bogus" in str(excinfo.value)
    assert "NTUSER.DAT" in str(excinfo.value)


def test_win_registry_get_missing_lib_raises_clear_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hive = _evidence_file(tmp_path, monkeypatch)
    monkeypatch.setitem(sys.modules, "Registry", None)

    with pytest.raises(win.RegistryToolError) as excinfo:
        win.win_registry_get(str(hive), "any")
    assert "python-registry not installed" in str(excinfo.value)


def test_win_registry_get_rejects_path_outside_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_dir = tmp_path / "input"
    input_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "INPUT_ROOT", input_dir.resolve())
    elsewhere = tmp_path / "elsewhere.dat"
    elsewhere.write_bytes(b"\x00")

    with pytest.raises(sandbox.SandboxViolation):
        win.win_registry_get(str(elsewhere), "any")
