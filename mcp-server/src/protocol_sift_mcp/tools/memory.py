"""Cross-OS memory analysis via Volatility 3 (stubs). TODO(W2-W4)."""

from __future__ import annotations

from typing import Any

from ..sandbox import assert_input_path


def memory_volatility(
    image_path: str,
    plugin: str,
    *,
    args: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """TODO(W2): Volatility 3 plugin invocation with structured JSON output.

    Plugin namespace examples:
      windows.pslist, windows.psscan, windows.malfind, windows.netscan,
      mac.pslist, mac.malfind, mac.netstat,
      linux.pslist, linux.bash, linux.malfind, linux.sockstat
    """
    _ = assert_input_path(image_path)
    raise NotImplementedError(f"memory_volatility {plugin} — implement W2-W4")
