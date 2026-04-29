# MemoryHound

**Drop-in DFIR superpowers for Claude Code.** Autonomous, cross-OS incident response triage with verifiable findings, signed attestations, and a tamper-evident audit trail.

Submission to the [SANS FIND EVIL!](https://findevil.devpost.com) Hackathon (Apr 15 – Jun 15, 2026).

> AI threats strike in minutes. Build the defender that responds in seconds.
> — SANS

## What This Is

MemoryHound turns Claude Code into an autonomous DFIR analyst. Drop evidence into a folder, run one command, get a signed forensic report.

Inspired by Daniel Miessler's [PAI](https://github.com/danielmiessler/PAI) pattern: the `.claude/` directory plus a custom MCP server give Claude the skills, agents, hooks, and forensic primitives to operate as a domain specialist — without modifying Claude itself.

```
You drop:    Evidence files (memory dumps, registry hives, EVTX, plist, etc.)
You run:     mh run <case-id>
You get:     Signed findings, investigative narrative, tamper-evident audit log
```

## Works With Both Auth Modes

MemoryHound is a layer on top of Claude Code. Whatever auth Claude Code uses, MemoryHound inherits.

- ✅ **Claude Pro / Max subscription** — `claude /login` once, you're done
- ✅ **Anthropic API key** — `export ANTHROPIC_API_KEY=sk-ant-...`
- ✅ **AWS Bedrock / Google Vertex** — set `CLAUDE_CODE_USE_BEDROCK=1` or `CLAUDE_CODE_USE_VERTEX=1`

## Quickstart

```bash
# 1. Clone + install (one time)
git clone https://github.com/saivarun3407/DFIR-AI.git memoryhound
cd memoryhound
./bin/mh init                                    # creates .venv, installs deps, generates ed25519 keys
./bin/mh doctor                                  # confirms env is healthy

# 2. Choose your auth (one time)
claude /login                                    # subscription
# OR
export ANTHROPIC_API_KEY=sk-ant-...             # API key

# 3. Drop evidence + run triage
mkdir -p cases/case-001/input
cp /path/to/evidence/* cases/case-001/input/
./bin/mh run case-001

# 4. Verify the chain + signature
./bin/mh verify case-001
```

Output lands in `cases/case-001/output/`:

| File | Purpose |
|---|---|
| `chain-of-custody.jsonl` | Tamper-evident hash-linked audit log |
| `findings.json` | Structured findings, every claim pinned |
| `narrative.md` | Investigator-ready prose report |
| `accuracy-report.md` | Honest FP / FN / hallucination tally |
| `case-<id>.attestation.json` | ed25519-signed SLSA-style provenance statement |

## See It Work In 60 Seconds (No API Key Needed)

The trust-chain demo proves the audit-trail mechanism without spending a token:

```bash
./bin/mh init       # if not already done
./bin/mh demo
```

Output:
```
» Step 1: chain_init (genesis entry)            ✓
» Step 2: ingest 2 artifacts (sha256+sha1)      ✓
» Step 3: simulate 3 tool calls                 ✓
» Step 4: verify chain — should be VALID        ✓
» Step 5: tamper one entry                      ✓
» Step 6: re-verify — should DETECT tamper      ✓ (chain INVALID)
» Step 7: restore + verify green again          ✓
```

This is the 15 seconds of footage that wins the hackathon's Audit Trail Quality criterion.

## Architecture

```
You → claude (CLI) → triage-orchestrator skill
                            │
        ┌───────────────────┼─────────────────────┬──────────┐
        ▼                   ▼                     ▼          ▼
  WindowsAgent         MacOSAgent            LinuxAgent   MemoryAgent
  (FOR500 KB)          (APFS + plist)        (journal)    (Volatility 3)
        │                   │                     │          │
        └───────┬───────────┴───────┬─────────────┘──────────┘
                ▼                   ▼
           Verifier        EvidenceCustodian
        (re-runs claims)   (hash chain, sign)
                │                   │
                └─────────┬─────────┘
                          ▼
              Custom MCP Server (Apache-2.0)
              ─ typed forensic primitives
              ─ NO shell, NO destructive ops
              ─ schema-enforced finding records
```

## Trust Stack — 7 Layers

| Layer | Mechanism |
|---|---|
| **1. Authenticity** | dual hash (sha256 + sha1) of evidence on ingest, read-only mount |
| **2. Validation** | magic-byte + format probe before any tool runs |
| **3. Verification** | every finding requires a pin (artifact + offset + tool + raw_excerpt); independent Verifier subagent re-runs |
| **4. Accountability** | tamper-evident JSONL audit log with sha256 hash chain |
| **5. Reproducibility** | pinned model + tool versions, `mh run` is replayable |
| **6. Provenance** | ed25519-signed SLSA-style attestations per case |
| **7. Honest Uncertainty** | confidence enum (`confirmed`/`inferred`/`uncertain`/`unknown`); refuses to hallucinate, acknowledges gaps |

## Supported Operating Systems

- **Windows** (10 / 11) — registry, EVTX, Prefetch, LNK, ShellBags, Recycle Bin, browser, USB, cloud connectors
- **macOS** — APFS, plist, Unified Logs (`tracev3`), KnowledgeC, Spotlight *(W3 in progress)*
- **Linux** — systemd journal, audit log, shell history, persistence vectors *(W4 in progress)*
- **Memory** (cross-OS) — Volatility 3 windows.* / mac.* / linux.* plugin families *(W2-W4)*

## CLI Reference

```
mh init [--with-forensics]   First-time setup: venv, deps, ed25519 keys.
                             --with-forensics adds heavy libs (Volatility, etc.)
mh doctor                    Health check across env, deps, auth, keys.
mh demo                      Trust-chain showcase — no real evidence, no tokens.
mh run <case-id>             Run Claude Code triage on cases/<id>/input/.
mh verify <case-id>          Verify chain-of-custody integrity for a case.
mh status                    List cases + their phase.
mh tools                     List MCP tools the agent can call.
mh check                     Quick env probe (exit 0/1).
```

## What's Real vs Stub

| Component | Status |
|---|---|
| Trust stack (hash chain, ed25519 sign, attestation) | ✅ live, tested, demoed |
| Sandbox (path-escape rejection, deny-list hooks) | ✅ live |
| `os_detect`, `magic_check` (cross-OS routing) | ✅ live (15 tests) |
| Windows tools: `win_registry_get`, `win_prefetch_parse`, `win_evtx_query`, `win_lnk_parse` | ✅ live (16 tests) |
| 11 Claude Code skills (full FOR500 / APFS / Linux content) | ✅ live |
| 5 specialist subagents | ✅ live |
| 5 hooks (guard / audit / finalize / etc.) | ✅ live |
| Pre-commit gate (ruff + pytest + license check) | ✅ live |
| `mh` CLI + `mh-mcp-server` portable launcher | ✅ live |
| `mac_*` macOS tools | 🛠️ W3 (May 10–16) |
| `linux_*` Linux tools | 🛠️ W4 (May 17–23) |
| `memory_volatility` wrapper | 🛠️ W2-W4 |

48 unit tests passing. CI green on every commit.

## Required Hackathon Deliverables (8 of 8)

| # | Deliverable | Where |
|---|---|---|
| 1 | Public GitHub repo (Apache-2.0) | this repo, [`LICENSE`](LICENSE) at root |
| 2 | Demo video < 5 min | *W6 — May 31 – Jun 6* |
| 3 | Architecture diagram | [`docs/architecture.md`](docs/architecture.md) |
| 4 | Project description | this README + [`docs/usage.md`](docs/usage.md) |
| 5 | Evidence dataset documentation | [`docs/dataset-documentation.md`](docs/dataset-documentation.md) |
| 6 | Accuracy report | [`docs/accuracy-report-template.md`](docs/) — populated per run |
| 7 | Deployment / setup instructions | this Quickstart + [`bin/mh`](bin/mh) installer |
| 8 | Agent execution logs (timestamps + tokens) | `cases/<id>/output/chain-of-custody.jsonl` |

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — full system design
- [`docs/usage.md`](docs/usage.md) — detailed usage walkthrough
- [`docs/development.md`](docs/development.md) — pre-commit + CI workflow
- [`docs/dataset-documentation.md`](docs/dataset-documentation.md) — evidence corpus + ground truth
- [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) — 51-day delivery plan

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

## Acknowledgments

- **SANS Institute** — SIFT Workstation, FOR500 / FOR518 / FOR577 curricula, FIND EVIL! hackathon
- **The DFIR community** — 19 years of open tooling
- **Volatility Foundation** — Volatility 3
- **Anthropic** — Claude Code, MCP
- **Daniel Miessler** — [PAI](https://github.com/danielmiessler/PAI) pattern for AI-as-domain-specialist
