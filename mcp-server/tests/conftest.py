"""Shared pytest fixtures."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _sandbox_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point sandbox roots at a per-test temp dir so tests can touch fake evidence."""
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    output_dir.mkdir()
    monkeypatch.setenv("EVIDENCE_PATH", str(input_dir))
    monkeypatch.setenv("OUTPUT_PATH", str(output_dir))

    import importlib

    from protocol_sift_mcp import sandbox

    importlib.reload(sandbox)
    os.environ["EVIDENCE_PATH"] = str(input_dir)
    os.environ["OUTPUT_PATH"] = str(output_dir)
