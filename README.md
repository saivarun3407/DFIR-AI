# MemoryHound

**Autonomous, cross-OS DFIR triage agent. Verifiable findings, signed attestations, tamper-evident audit trail.**

Submission to the [SANS FIND EVIL!](https://findevil.devpost.com) Hackathon (Apr 15 – Jun 15, 2026).

> AI threats strike in minutes. Build the defender that responds in seconds.
> — SANS

MemoryHound extends [Protocol SIFT](https://github.com/teamdfir/protocol-sift) with autonomous Windows / macOS / Linux incident-response triage. Built on Claude Code with a custom MCP server providing typed forensic primitives, a self-correcting verifier loop, and a 7-layer trust stack so every finding is provably yours and every step is provably ours.

## Core Properties

| Property | Mechanism |
|---|---|
| **Authenticity** | dual hash (sha256 + sha1) of evidence on ingest, read-only mount |
| **Validation** | magic-byte + format probe before any tool runs |
| **Verification** | every finding requires evidence pin (artifact + offset + tool); independent Verifier subagent re-runs |
| **Accountability** | tamper-evident JSONL audit log with hash chain |
| **Reproducibility** | pinned model + tool versions, `replay.sh`, deterministic where possible |
| **Provenance** | ed25519-signed SLSA-style attestations per case |
| **Honest Uncertainty** | confidence enum (`confirmed | inferred | uncertain | unknown`); refuses to hallucinate |

## Supported Operating Systems

- **Windows** (10 / 11) — registry, EVTX, Prefetch, LNK, ShellBags, Recycle Bin, browser, USB, cloud connectors
- **macOS** — APFS, plist, Unified Logs (`tracev3`), KnowledgeC, Spotlight
- **Linux** — systemd journal, audit log, shell history, persistence vectors, container artifacts
- **Memory** (cross-OS) — Volatility 3 windows.* / mac.* / linux.* plugin families

## Architecture

```
Claude Code (orchestrator skill: triage-orchestrator)
   ├── WindowsAgent     (FOR500 knowledge base)
   ├── MacOSAgent       (APFS + plist + tracev3)
   ├── LinuxAgent       (journal + audit + history)
   ├── MemoryAgent      (cross-OS Volatility 3)
   ├── Verifier         (re-runs every claim)
   └── EvidenceCustodian (hash, sign, chain)
        │
        ▼
Custom MCP Server (Apache-2.0)
   - typed forensic primitives only
   - NO shell, NO destructive ops
   - schema-enforced finding records
```

See [`docs/architecture.md`](docs/architecture.md) for the full picture.

## Quickstart

```bash
# Prereq: SIFT Workstation OVA, Docker, Anthropic API key
git clone <repo>
cd memory-hound
./scripts/install.sh        # set up MCP server + dev deps
docker compose up -d        # sandbox + read-only evidence mount

# Run on a sample case
export CASE_ID=demo-001
export EVIDENCE_PATH=/path/to/sample.dmp
claude code --skills .claude/skills/triage-orchestrator
```

## Required Hackathon Deliverables

| # | Deliverable | Location |
|---|---|---|
| 1 | Public GitHub repo (Apache-2.0) | this repo, `LICENSE` at root |
| 2 | Demo video < 5 min | `docs/demo-video.md` (link) |
| 3 | Architecture diagram | `docs/architecture.svg` |
| 4 | Project description | this README + `docs/usage.md` |
| 5 | Evidence dataset documentation | `docs/dataset-documentation.md` |
| 6 | Accuracy report | `docs/accuracy-report.md` |
| 7 | Deployment / setup instructions | `scripts/install.sh` + this Quickstart |
| 8 | Agent execution logs (timestamps + tokens) | `output/agent.log.jsonl` (per run) |

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

## Acknowledgments

- SANS Institute — SIFT Workstation, FOR500 / FOR518 / FOR577 curricula, FIND EVIL! hackathon
- The DFIR community — 19 years of open tooling
- Volatility Foundation — Volatility 3
- Anthropic — Claude Code, MCP
