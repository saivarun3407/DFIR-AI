"""Sandbox enforcement helpers — path safety, no-shell, evidence read-only."""

from __future__ import annotations

import os
from pathlib import Path

INPUT_ROOT = Path(os.environ.get("EVIDENCE_PATH", "/input")).resolve()
OUTPUT_ROOT = Path(os.environ.get("OUTPUT_PATH", "/output")).resolve()


class SandboxViolation(Exception):
    """Raised when a tool tries to escape the sandbox."""


def assert_input_path(path: str | Path) -> Path:
    """Resolve and verify a path is inside the read-only evidence mount."""
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(INPUT_ROOT)
    except ValueError as exc:
        raise SandboxViolation(
            f"Path {resolved} escapes evidence root {INPUT_ROOT}. Evidence is read-only and isolated."
        ) from exc
    if not resolved.exists():
        raise SandboxViolation(f"Path {resolved} does not exist under evidence root.")
    return resolved


def assert_output_path(path: str | Path) -> Path:
    """Resolve and verify a path is inside the writable output area."""
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(OUTPUT_ROOT)
    except ValueError as exc:
        raise SandboxViolation(
            f"Path {resolved} escapes output root {OUTPUT_ROOT}. Writes confined to /output."
        ) from exc
    return resolved
