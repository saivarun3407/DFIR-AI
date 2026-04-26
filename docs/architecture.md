# MemoryHound Architecture

## High-level

```
┌──────────────────────────────────────────────────────────────────┐
│   Claude Code (Direct Agent Extension of Protocol SIFT)          │
│   - skill: triage-orchestrator                                   │
│   - hooks: SessionStart, PreToolUse, PostToolUse, Stop           │
└────────────────────────────┬─────────────────────────────────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       │                     │                     │
       ▼                     ▼                     ▼
┌─────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ WindowsAgent│   │ MacOSAgent       │   │ LinuxAgent       │
│ (FOR500)    │   │ (FOR518 + APFS)  │   │ (FOR577 baseline)│
└──────┬──────┘   └────────┬─────────┘   └────────┬─────────┘
       │                   │                       │
       └────────┬──────────┴────────┬──────────────┘
                ▼                   ▼
       ┌──────────────────┐  ┌──────────────────┐
       │ Verifier         │  │ EvidenceCustodian│
       │ (re-runs claims) │  │ (hash, sign)     │
       └────────┬─────────┘  └────────┬─────────┘
                │                     │
                └──────────┬──────────┘
                           ▼
       ┌─────────────────────────────────────────────┐
       │  Custom MCP Server (Apache-2.0)             │
       │  - typed forensic primitives                │
       │  - chain-of-custody hash chain              │
       │  - finding_record (rejects un-pinned)       │
       │  - sign / attest                            │
       └─────────────────────────────────────────────┘
                           │
                           ▼
       ┌─────────────────────────────────────────────┐
       │  Sandboxed forensic toolchain               │
       │  - Volatility 3 (windows.* / mac.* / linux.*)│
       │  - python-evtx, python-registry             │
       │  - apfs-fuse, plistlib                      │
       │  - systemd journal reader, audit parser     │
       │  - YARA, libmagic, pefile                   │
       └─────────────────────────────────────────────┘
```

## Trust Stack (7 Layers)

1. **Authenticity** — dual hash (sha256 + sha1) on ingest, read-only mount
2. **Validation** — magic-byte + format probe before tool execution
3. **Verification** — evidence pin + Verifier re-run + cross-artifact corroboration
4. **Accountability** — tamper-evident JSONL hash chain
5. **Reproducibility** — pinned model + tool versions, `replay.sh`
6. **Provenance** — ed25519 signed SLSA-style attestations
7. **Honest Uncertainty** — confidence enum + acknowledged gaps

See [`SYNTHESIS_FOR_MEMORYHOUND.md`](../../sans-docs/SYNTHESIS_FOR_MEMORYHOUND.md) for full source-derivation.

## Data Flow Per Case

1. Operator drops evidence into `/input/` (read-only mount)
2. `SessionStart` hook hashes everything, writes genesis chain entry
3. `triage-orchestrator` calls `os_detect` per artifact
4. Routes to Windows/Mac/Linux/Memory subagent
5. Subagent calls typed MCP tools, every claim gets a Pin
6. Each `finding_record` triggers `Verifier` subagent re-run
7. Disagreements → revision; agreements → finalize
8. `Stop` hook verifies chain, signs findings, writes attestation
9. Output: `findings.json`, `narrative.md`, `accuracy-report.md`, `chain-of-custody.jsonl`, `case-<id>.attestation.json`

## Why This Wins The Rubric

| Judging Criterion | Our Mechanism |
|---|---|
| Autonomous Execution Quality (tiebreaker) | self-correct loop + Verifier dissent flow |
| IR Accuracy | evidence pinning + cross-corroboration + hallucination corpus |
| Breadth & Depth of Analysis | cross-OS coverage + memory + filesystem + logs |
| Constraint Implementation | typed MCP w/ explicit deny list, no-shell, sandbox at FS layer |
| Audit Trail Quality | hash-chained JSONL, tamper-evident, replayable |
| Usability & Documentation | replay.sh, install.sh, this doc, dataset-documentation.md |
