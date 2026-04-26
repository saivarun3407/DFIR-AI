---
name: self-correct
description: Verify-then-report loop. Before finalizing any finding, an independent Verifier subagent re-runs the cited tool against the same evidence and confirms the excerpt matches. If disagreement, the original agent revises. This is the tiebreaker mechanism for the SANS judging rubric.
---

# Self-Correct Loop

The hackathon's tiebreaker is "Autonomous Execution Quality — does the agent reason, handle failures, and self-correct in real time?" This skill is how we win that.

## The Loop

```
agent claim → record finding → spawn Verifier → verify_result
   │                                                  │
   │                     ┌────────────────────────────┘
   │                     ▼
   │            agree?  ───── yes ──→ finalize finding
   │                     │
   │                     no
   │                     ▼
   │            verifier dissent  ←──┐
   │                     │            │
   │                     ▼            │
   │            spawn agent w/ dissent payload
   │                     │            │
   │                     ▼            │
   │            agent revises ────────┘ (max 2 retries)
   │                                  │
   └──────────────────────────────────┘
                if 3rd disagreement → mark `requires_human_review`
```

## Verifier Subagent Contract

Verifier receives:
```json
{
  "claim": "Process injection in explorer.exe (PID 4216)",
  "confidence": "inferred",
  "pins": [{"artifact":"memory.dmp","tool":"windows.malfind","locator":{...},"raw_excerpt":"..."}]
}
```

Verifier must:
1. Re-run the exact same MCP tool with the same args
2. Re-extract the cited locator
3. Compare actual bytes/values to claimed `raw_excerpt`
4. Apply confidence enum independently
5. Return:
```json
{
  "verifier_decision": "agree | dissent | tool_failure | excerpt_mismatch",
  "verifier_confidence": "...",
  "delta": "<what was different, if any>",
  "recommendation": "accept | revise | discard | escalate_human"
}
```

## When Verifier Disagrees

Original agent receives the dissent and MUST revise — cannot simply re-submit identical claim. Two outcomes accepted:

1. **Agent accepts dissent** → adjust confidence down OR change claim to match verifier's view
2. **Agent supplies additional pins** → submit revised finding with extra evidence sources

After 2 revision rounds, if no convergence: log `event:requires_human_review` in the chain.

## Demo Beat (for hackathon video)

Stage one wrong-then-corrected sequence on Cridex sample:
1. Agent claims `cridex.exe` (PID 1640) is the malicious process
2. Verifier checks `pslist`, finds PID 1640 is `reader_sl.exe` not `cridex.exe`
3. Agent revises: actual cridex PID per `psscan` is 1484
4. Verifier confirms PID 1484 = cridex.exe = `confirmed`
5. Audit log shows the correction event

This 30-second sequence is the most important footage in the demo video. Rehearse it five times.

## Discipline

Do NOT:
- Spawn Verifier with extra hints or context that bias agreement
- Accept verifier output that itself was un-pinned
- Skip the verifier on "obvious" findings — every finding goes through, no exceptions

Honest convergence > false confidence.
