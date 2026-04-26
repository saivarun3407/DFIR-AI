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


# ─── Prefetch ────────────────────────────────────────────────────────────────


def _install_fake_prefetch(monkeypatch: pytest.MonkeyPatch, prefetch_obj: object) -> None:
    fake_module = SimpleNamespace(Prefetch=MagicMock(return_value=prefetch_obj))
    monkeypatch.setitem(sys.modules, "windowsprefetch", fake_module)


def test_win_prefetch_parse_returns_structured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pf_path = _evidence_file(tmp_path, monkeypatch, "CMD.EXE-A1B2C3D4.pf")
    fake_pf = SimpleNamespace(
        executableName="CMD.EXE",
        version=30,
        runCount=42,
        lastRunTime=[
            datetime(2026, 4, 25, 10, 0, tzinfo=UTC),
            datetime(2026, 4, 24, 9, 0, tzinfo=UTC),
        ],
        volumesInformation=[{"name": r"\\?\Volume{abc}", "creation_time": "2024-01-01"}],
        filesAccessed=[r"\Windows\System32\cmd.exe", r"\Windows\System32\kernel32.dll"],
        directoryStrings=[r"\Windows\System32"],
    )
    _install_fake_prefetch(monkeypatch, fake_pf)

    result = win.win_prefetch_parse(str(pf_path))

    assert result["executable_name"] == "CMD.EXE"
    assert result["version"] == 30
    assert result["run_count"] == 42
    assert len(result["last_run_times"]) == 2
    assert result["last_run_times"][0] == "2026-04-25T10:00:00+00:00"
    assert len(result["files_accessed"]) == 2


def test_win_prefetch_parse_handles_single_timestamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pf_path = _evidence_file(tmp_path, monkeypatch, "FOO.EXE-X.pf")
    fake_pf = SimpleNamespace(
        executableName="FOO.EXE",
        version=23,
        runCount=1,
        lastRunTime=datetime(2026, 4, 25, 10, 0, tzinfo=UTC),
        volumesInformation=[],
        filesAccessed=[],
        directoryStrings=[],
    )
    _install_fake_prefetch(monkeypatch, fake_pf)

    result = win.win_prefetch_parse(str(pf_path))
    assert result["last_run_times"] == ["2026-04-25T10:00:00+00:00"]


def test_win_prefetch_parse_missing_lib(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pf_path = _evidence_file(tmp_path, monkeypatch, "X.pf")
    monkeypatch.setitem(sys.modules, "windowsprefetch", None)
    with pytest.raises(win.PrefetchToolError) as excinfo:
        win.win_prefetch_parse(str(pf_path))
    assert "windowsprefetch not installed" in str(excinfo.value)


def test_win_prefetch_parse_rejects_path_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_dir = tmp_path / "input"
    input_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "INPUT_ROOT", input_dir.resolve())
    outside = tmp_path / "evil.pf"
    outside.write_bytes(b"\x00")
    with pytest.raises(sandbox.SandboxViolation):
        win.win_prefetch_parse(str(outside))


# ─── EVTX ────────────────────────────────────────────────────────────────────


def _make_evtx_record(record_id: str, eid: int, time_iso: str, channel: str) -> MagicMock:
    rec = MagicMock()
    rec.xml.return_value = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f"<System>"
        f'<EventID>{eid}</EventID>'
        f'<EventRecordID>{record_id}</EventRecordID>'
        f"<Channel>{channel}</Channel>"
        f'<TimeCreated SystemTime="{time_iso}" />'
        f"<Computer>WIN-DESKTOP</Computer>"
        f"</System>"
        f"</Event>"
    )
    return rec


def _install_fake_evtx(monkeypatch: pytest.MonkeyPatch, log_obj: MagicMock) -> None:
    fake_evtx_module = SimpleNamespace(Evtx=MagicMock(return_value=log_obj))
    fake_pkg = SimpleNamespace(Evtx=fake_evtx_module)
    monkeypatch.setitem(sys.modules, "Evtx", fake_pkg)
    monkeypatch.setitem(sys.modules, "Evtx.Evtx", fake_evtx_module)


def _make_log_with_records(records: list[MagicMock]) -> MagicMock:
    log = MagicMock()
    log.__enter__ = MagicMock(return_value=log)
    log.__exit__ = MagicMock(return_value=False)
    log.records.return_value = iter(records)
    return log


def test_win_evtx_query_returns_filtered_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_path = _evidence_file(tmp_path, monkeypatch, "Security.evtx")
    records = [
        _make_evtx_record("18342", 4624, "2026-04-25T10:00:00.000Z", "Security"),
        _make_evtx_record("18343", 4625, "2026-04-25T10:01:00.000Z", "Security"),
        _make_evtx_record("18344", 4624, "2026-04-25T10:02:00.000Z", "Security"),
    ]
    log = _make_log_with_records(records)
    _install_fake_evtx(monkeypatch, log)

    result = win.win_evtx_query(str(log_path), event_ids=[4624])

    assert len(result) == 2
    assert all(r["eid"] == 4624 for r in result)
    assert result[0]["record_id"] == "18342"
    assert result[0]["channel"] == "Security"
    assert result[0]["computer"] == "WIN-DESKTOP"
    assert result[0]["time_created"] == "2026-04-25T10:00:00.000Z"


def test_win_evtx_query_respects_time_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_path = _evidence_file(tmp_path, monkeypatch, "Security.evtx")
    records = [
        _make_evtx_record("1", 4624, "2026-04-25T09:00:00.000Z", "Security"),
        _make_evtx_record("2", 4624, "2026-04-25T10:00:00.000Z", "Security"),
        _make_evtx_record("3", 4624, "2026-04-25T11:00:00.000Z", "Security"),
    ]
    log = _make_log_with_records(records)
    _install_fake_evtx(monkeypatch, log)

    result = win.win_evtx_query(
        str(log_path),
        time_range=("2026-04-25T09:30:00.000Z", "2026-04-25T10:30:00.000Z"),
    )

    assert len(result) == 1
    assert result[0]["record_id"] == "2"


def test_win_evtx_query_respects_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_path = _evidence_file(tmp_path, monkeypatch, "Security.evtx")
    records = [_make_evtx_record(str(i), 4624, "2026-04-25T10:00:00.000Z", "Security") for i in range(50)]
    log = _make_log_with_records(records)
    _install_fake_evtx(monkeypatch, log)

    result = win.win_evtx_query(str(log_path), limit=10)
    assert len(result) == 10


def test_win_evtx_query_missing_lib(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_path = _evidence_file(tmp_path, monkeypatch, "Security.evtx")
    monkeypatch.setitem(sys.modules, "Evtx", None)
    monkeypatch.setitem(sys.modules, "Evtx.Evtx", None)
    with pytest.raises(win.EvtxToolError):
        win.win_evtx_query(str(log_path))


# ─── LNK ─────────────────────────────────────────────────────────────────────


def _install_fake_lnk(monkeypatch: pytest.MonkeyPatch, link_obj: object) -> None:
    fake_module = SimpleNamespace(parse=MagicMock(return_value=link_obj))
    monkeypatch.setitem(sys.modules, "pylnk3", fake_module)


def test_win_lnk_parse_returns_structured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lnk_path = _evidence_file(tmp_path, monkeypatch, "report.lnk")
    fake_link = SimpleNamespace(
        path=r"D:\report.docx",
        working_dir="D:\\",
        arguments=None,
        description=None,
        machine_id="WIN-DESKTOP",
        drive_serial="ABCD-1234",
        drive_type="DRIVE_REMOVABLE",
        creation_time=datetime(2026, 4, 20, 12, 0, tzinfo=UTC),
        modification_time=datetime(2026, 4, 25, 9, 0, tzinfo=UTC),
        access_time=datetime(2026, 4, 25, 10, 0, tzinfo=UTC),
        file_size=12345,
        network_share_name=None,
    )
    _install_fake_lnk(monkeypatch, fake_link)

    result = win.win_lnk_parse(str(lnk_path))

    assert result["target"] == r"D:\report.docx"
    assert result["machine_id"] == "WIN-DESKTOP"
    assert result["drive_serial"] == "ABCD-1234"
    assert result["drive_type"] == "DRIVE_REMOVABLE"
    assert result["creation_time"] == "2026-04-20T12:00:00+00:00"
    assert result["file_size"] == 12345


def test_win_lnk_parse_missing_lib(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lnk_path = _evidence_file(tmp_path, monkeypatch, "x.lnk")
    monkeypatch.setitem(sys.modules, "pylnk3", None)
    with pytest.raises(win.LnkToolError):
        win.win_lnk_parse(str(lnk_path))
