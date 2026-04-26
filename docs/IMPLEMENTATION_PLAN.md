# MemoryHound 51-Day Implementation Plan

**Target submission:** Jun 13, 2026 (48-hr buffer before Jun 15 deadline)
**Effort:** Solo, full-time

## Week 1 — Apr 25–May 2 — Foundation + Trust Layer

- [x] Repo scaffold (LICENSE Apache-2.0 at top, .claude/, mcp-server/, docs/)
- [x] Trust primitives: hash, chain_init/append/verify, sign, attest
- [x] Schema: Finding + Pin + Locator + ChainEntry (Pydantic)
- [x] Sandbox helpers (assert_input_path, assert_output_path)
- [x] Hooks: SessionStart, PreToolUse (deny-list), PostToolUse (chain append), Stop (sign)
- [x] Tests: hash chain tamper detection, ed25519 sign/verify, sandbox escape
- [ ] Set up SIFT Workstation VM
- [ ] Install Protocol SIFT (`teamdfir/protocol-sift`)
- [ ] Verify Claude Code + MCP wiring end-to-end with stub `hash` call
- [ ] Generate signing keypair, commit pubkey only
- [ ] CI: license-check + ruff + mypy + pytest passing on main

## Week 2 — May 3–9 — Windows Depth (highest artifact density)

- [ ] `win_registry_get` — python-registry, RegRipper-style typed reads
- [ ] `win_evtx_query` — python-evtx with EID + time-range filter
- [ ] `win_prefetch_parse` — last 8 exec times, run count
- [ ] `win_lnk_parse` — shellitem details, target MACB, volume info
- [ ] `win_shellbag_parse` — USRCLASS.DAT folder access
- [ ] `win_recyclebin_parse` — $I/$R pairs
- [ ] `win_ese_query` — SRUDB.dat, Windows.edb, WebCacheV01.dat
- [ ] `memory_volatility(plugin="windows.*")` — pslist, malfind, netscan, dlllist, cmdline, handles
- [ ] First end-to-end run: WindowsAgent triage on Cridex memory sample
- [ ] Self-correct loop wired (Verifier subagent)
- [ ] Demo-rehearsal: deliberate-wrong-then-corrected sequence

## Week 3 — May 10–16 — macOS Triage

- [ ] `mac_apfs_inspect` — apfs-fuse + custom B-tree walker
- [ ] `mac_plist_get` — plistlib + key path traversal
- [ ] `mac_tracev3_query` — Unified Logs (predicate filter)
- [ ] `mac_knowledgec_query` — SQLite + stream type decoding
- [ ] `mac_spotlight_query` — .Spotlight-V100 metadata
- [ ] `memory_volatility(plugin="mac.*")`
- [ ] MacOSAgent end-to-end on a sample dump
- [ ] iOS app artifact paths embedded in skill (40+ apps from booklet)

## Week 4 — May 17–23 — Linux Triage + Cross-OS Routing

- [ ] `linux_journal_query` — systemd journal reader
- [ ] `linux_audit_query` — auditd log parser
- [ ] `linux_history_parse` — bash/zsh w/ HISTTIMEFORMAT
- [ ] `linux_systemd_units` — full unit enumeration
- [ ] `linux_cron_parse` — all cron locations
- [ ] `memory_volatility(plugin="linux.*")`
- [ ] LinuxAgent end-to-end on SSH-compromise sample
- [ ] `os_detect` MCP tool with 3-signal confidence
- [ ] triage-orchestrator routes correctly across all 3 OS

## Week 5 — May 24–30 — Trust Hardening + Eval

- [ ] Hallucination corpus (3 clean dumps) — agent must produce 0 findings
- [ ] Cross-corroboration logic in skills (Prefetch + BAM + UserAssist alignment)
- [ ] `verify_excerpt` server-side check (rejects pin where bytes don't match)
- [ ] Attestation verification script for judges (`scripts/verify_attestation.py`)
- [ ] Run all 5+ corpora via `eval.sh`, generate per-case accuracy reports
- [ ] Architecture diagram (mermaid → SVG)

## Week 6 — May 31–Jun 6 — Documentation + Demo Video v1

- [ ] README polish — every required deliverable mapped
- [ ] dataset-documentation.md complete with hashes
- [ ] usage.md with screenshots
- [ ] First demo video draft (5-min)
  - Hash on ingest
  - Windows triage with cite
  - Self-correction beat
  - macOS auto-route
  - Live tamper detection
  - Honest accuracy report read aloud
- [ ] Independent review by DFIR friend (if available)

## Week 7 — Jun 7–13 — Polish + Submit

- [ ] Demo video v2 (final cut)
- [ ] Accuracy report final w/ all corpora
- [ ] Verify LICENSE at top of repo
- [ ] Verify all 8 hackathon deliverables present
- [ ] Submit on Devpost on Jun 13 EOD
- [ ] Verify submission renders correctly on Devpost

## Week 8 — Jun 14–15 — Buffer

- [ ] Fix any caught issues
- [ ] Resubmit if needed (rules permit)

## Daily Rituals

- Morning: read latest hackathon Updates page + Slack
- Stand-up to self: yesterday's progress vs plan, today's target
- Evening: commit + push, run CI, update plan checkboxes
- Weekly Sunday: integration run end-to-end, no skipped tests
