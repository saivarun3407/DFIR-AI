"""Sandbox tests — paths outside /input must be rejected."""

from __future__ import annotations

from pathlib import Path

import pytest

from protocol_sift_mcp import sandbox


def test_input_path_inside_evidence_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    input_dir = tmp_path / "input"
    monkeypatch.setattr(sandbox, "INPUT_ROOT", input_dir.resolve())
    artifact = input_dir / "memory.dmp"
    artifact.write_bytes(b"\x00")
    resolved = sandbox.assert_input_path(artifact)
    assert resolved == artifact.resolve()


def test_input_path_rejects_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    input_dir = tmp_path / "input"
    input_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "INPUT_ROOT", input_dir.resolve())
    elsewhere = tmp_path / "elsewhere.bin"
    elsewhere.write_bytes(b"\x00")
    with pytest.raises(sandbox.SandboxViolation):
        sandbox.assert_input_path(elsewhere)


def test_input_path_rejects_traversal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    input_dir = tmp_path / "input"
    input_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "INPUT_ROOT", input_dir.resolve())
    with pytest.raises(sandbox.SandboxViolation):
        sandbox.assert_input_path(input_dir / ".." / "secret.txt")


def test_output_path_inside_output_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_dir = tmp_path / "output"
    monkeypatch.setattr(sandbox, "OUTPUT_ROOT", output_dir.resolve())
    p = sandbox.assert_output_path(output_dir / "findings.json")
    assert p == (output_dir / "findings.json").resolve()


def test_output_path_rejects_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "OUTPUT_ROOT", output_dir.resolve())
    with pytest.raises(sandbox.SandboxViolation):
        sandbox.assert_output_path(tmp_path / "elsewhere.json")
