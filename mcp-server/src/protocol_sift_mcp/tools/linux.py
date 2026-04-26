"""Linux DFIR primitives (stubs). TODO(W4) implementation."""

from __future__ import annotations

from typing import Any

from ..sandbox import assert_input_path


def linux_journal_query(
    journal_dir: str,
    *,
    unit: str | None = None,
    since: str | None = None,
    until: str | None = None,
    predicate: str | None = None,
) -> list[dict[str, Any]]:
    """TODO(W4): systemd-journalctl-style query against journal files."""
    _ = assert_input_path(journal_dir)
    raise NotImplementedError("linux_journal_query — implement W4")


def linux_audit_query(
    audit_log_path: str,
    *,
    syscall: str | None = None,
    time_range: tuple[str, str] | None = None,
) -> list[dict[str, Any]]:
    """TODO(W4): Parse audit.log with event correlation."""
    _ = assert_input_path(audit_log_path)
    raise NotImplementedError("linux_audit_query — implement W4")


def linux_history_parse(history_path: str) -> list[dict[str, Any]]:
    """TODO(W4): Parse bash/zsh history with HISTTIMEFORMAT decoding."""
    _ = assert_input_path(history_path)
    raise NotImplementedError("linux_history_parse — implement W4")


def linux_systemd_units(image_path: str) -> list[dict[str, Any]]:
    """TODO(W4): Enumerate units from /etc/systemd, /lib/systemd, ~/.config/systemd/user."""
    _ = assert_input_path(image_path)
    raise NotImplementedError("linux_systemd_units — implement W4")


def linux_cron_parse(image_path: str) -> list[dict[str, Any]]:
    """TODO(W4): Parse all cron locations: /etc/crontab, /etc/cron.*, /var/spool/cron/."""
    _ = assert_input_path(image_path)
    raise NotImplementedError("linux_cron_parse — implement W4")
