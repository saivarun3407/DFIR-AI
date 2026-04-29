"""macOS tool tests. mac_plist_get + mac_knowledgec_query use stdlib so tests
can build real fixture files instead of mocking the parser.
"""

from __future__ import annotations

import plistlib
import sqlite3
from pathlib import Path

import pytest

from protocol_sift_mcp import sandbox
from protocol_sift_mcp.tools import macos as mac


def _evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str) -> Path:
    indir = tmp_path / "input"
    indir.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "INPUT_ROOT", indir.resolve())
    return indir / name


# ─── mac_plist_get ───────────────────────────────────────────────────────────


def test_mac_plist_get_binary_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = _evidence(tmp_path, monkeypatch, "preferences.plist")
    data = {
        "AppleLocale": "en_US",
        "NSRecentDocuments": ["/Users/x/report.docx", "/Users/x/notes.md"],
        "DSAToken": b"\xde\xad\xbe\xef",
    }
    with f.open("wb") as out:
        plistlib.dump(data, out, fmt=plistlib.FMT_BINARY)

    result = mac.mac_plist_get(str(f))

    assert result["format"] == "binary"
    assert set(result["root_keys"]) == {"AppleLocale", "NSRecentDocuments", "DSAToken"}
    assert result["value"]["AppleLocale"] == "en_US"
    assert result["value"]["DSAToken"] == "deadbeef"  # bytes → hex


def test_mac_plist_get_xml_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = _evidence(tmp_path, monkeypatch, "Info.plist")
    with f.open("wb") as out:
        plistlib.dump({"CFBundleIdentifier": "com.apple.dock"}, out, fmt=plistlib.FMT_XML)

    result = mac.mac_plist_get(str(f))
    assert result["format"] == "xml"
    assert result["value"]["CFBundleIdentifier"] == "com.apple.dock"


def test_mac_plist_get_traverses_dot_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = _evidence(tmp_path, monkeypatch, "complex.plist")
    data = {
        "Apps": {
            "com.apple.finder": {
                "LastLaunch": "2026-04-25T10:00:00Z",
                "RecentDocs": ["a", "b", "c"],
            }
        }
    }
    with f.open("wb") as out:
        plistlib.dump(data, out, fmt=plistlib.FMT_BINARY)

    r1 = mac.mac_plist_get(str(f), "Apps/com.apple.finder/LastLaunch")
    assert r1["value"] == "2026-04-25T10:00:00Z"
    assert r1["key_path"] == "Apps/com.apple.finder/LastLaunch"

    r2 = mac.mac_plist_get(str(f), "Apps/com.apple.finder/RecentDocs/1")
    assert r2["value"] == "b"


def test_mac_plist_get_invalid_key_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = _evidence(tmp_path, monkeypatch, "x.plist")
    with f.open("wb") as out:
        plistlib.dump({"a": 1}, out, fmt=plistlib.FMT_BINARY)
    with pytest.raises(mac.PlistToolError):
        mac.mac_plist_get(str(f), "a/does_not_exist")


def test_mac_plist_get_corrupted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = _evidence(tmp_path, monkeypatch, "garbage.plist")
    f.write_bytes(b"not a plist at all")
    with pytest.raises(mac.PlistToolError):
        mac.mac_plist_get(str(f))


def test_mac_plist_get_rejects_path_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    indir = tmp_path / "input"
    indir.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "INPUT_ROOT", indir.resolve())
    elsewhere = tmp_path / "outside.plist"
    elsewhere.write_bytes(b"")
    with pytest.raises(sandbox.SandboxViolation):
        mac.mac_plist_get(str(elsewhere))


# ─── mac_knowledgec_query ────────────────────────────────────────────────────


def _make_knowledgec(path: Path) -> None:
    """Build a minimal knowledgeC.db-shaped sqlite for testing."""
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE ZOBJECT (
            Z_PK INTEGER PRIMARY KEY,
            ZSTREAMNAME TEXT,
            ZVALUESTRING TEXT,
            ZSTARTDATE REAL,
            ZENDDATE REAL
        );
        INSERT INTO ZOBJECT (ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE)
            VALUES ('/app/usage', 'com.apple.Safari', 738968400.0, 738968460.0),
                   ('/app/usage', 'com.apple.Terminal', 738968500.0, 738968800.0),
                   ('/app/inFocus', 'com.apple.Safari', 738968400.0, 738968420.0);
        """
    )
    conn.commit()
    conn.close()


def test_mac_knowledgec_query_by_table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = _evidence(tmp_path, monkeypatch, "knowledgeC.db")
    _make_knowledgec(f)
    result = mac.mac_knowledgec_query(str(f), table="ZOBJECT", limit=10)
    assert len(result) == 3
    apps = {r["ZVALUESTRING"] for r in result}
    assert apps == {"com.apple.Safari", "com.apple.Terminal"}


def test_mac_knowledgec_query_select_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = _evidence(tmp_path, monkeypatch, "knowledgeC.db")
    _make_knowledgec(f)
    result = mac.mac_knowledgec_query(
        str(f),
        sql="SELECT ZVALUESTRING FROM ZOBJECT WHERE ZSTREAMNAME='/app/usage'",
        limit=10,
    )
    assert len(result) == 2


def test_mac_knowledgec_query_rejects_non_select(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = _evidence(tmp_path, monkeypatch, "knowledgeC.db")
    _make_knowledgec(f)
    with pytest.raises(ValueError, match="SELECT"):
        mac.mac_knowledgec_query(str(f), sql="DELETE FROM ZOBJECT")


def test_mac_knowledgec_query_rejects_unsafe_table_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = _evidence(tmp_path, monkeypatch, "knowledgeC.db")
    _make_knowledgec(f)
    with pytest.raises(ValueError, match="Invalid table name"):
        mac.mac_knowledgec_query(str(f), table="ZOBJECT; DROP TABLE foo")


def test_mac_knowledgec_query_requires_one_of_sql_or_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = _evidence(tmp_path, monkeypatch, "knowledgeC.db")
    _make_knowledgec(f)
    with pytest.raises(ValueError, match="exactly one"):
        mac.mac_knowledgec_query(str(f))
    with pytest.raises(ValueError, match="exactly one"):
        mac.mac_knowledgec_query(str(f), sql="SELECT * FROM ZOBJECT", table="ZOBJECT")
