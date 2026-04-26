---
name: accuracy-report
description: Generates the honest accuracy report — true positives, false positives, false negatives, hallucinations, acknowledged gaps. Required hackathon deliverable. Honesty wins points; inflated claims lose them.
---

# Accuracy Report

The hackathon judges this under "IR Accuracy". Brutal honesty scores higher than polished optimism — judges are senior DFIR practitioners who detect inflated claims instantly.

## Required Sections

### 1. Run Metadata
- Case ID, evidence inventory (filenames + sha256)
- Model version, tool versions
- Total findings, breakdown by confidence enum

### 2. Confusion Matrix (vs ground truth)

| | Ground Truth: Threat | Ground Truth: Benign |
|---|---|---|
| **Agent reported: Threat** | TP | FP (false positive) |
| **Agent reported: Benign** | FN (missed) | TN |

For each: count + sample finding IDs.

### 3. Hallucination Tally
A hallucination is a claim with no valid pin OR a pin whose excerpt doesn't match evidence. The MCP server prevents most by schema enforcement, but list any caught + how (verifier dissent, manual review, etc.).

**Hallucination corpus result:** Run on the 3 deliberately-clean evidence dumps. Expect zero findings. Report any claims made on these — each is a hallucination.

### 4. Acknowledged Gaps
Every `gap_acknowledged` event from the chain. These count POSITIVELY — judges see honest discipline.

### 5. Self-Correction Events
Every `self_correction` event from the chain. Show the agent caught its own mistakes mid-run.

### 6. Tool Failures
Every `tool_failure`. Don't hide. Show what didn't work and how the agent handled it (gap_acknowledged vs alternative tool).

### 7. Time + Cost
- Wall-clock per case
- Total tokens (input + output)
- Estimated $ at current Claude pricing
- Time-to-first-finding

### 8. Reproducibility Statement
- "This run is reproducible via `./scripts/replay.sh <case_id>`"
- Document any non-determinism source (LLM stochasticity, tool timing, etc.)
- Provide expected drift envelope (e.g., "≤2 findings drift run-to-run on identical evidence")

## Template

Output to `/output/accuracy-report.md`. Use this skeleton:

```markdown
# Accuracy Report — Case <CASE_ID>

## Run Metadata
- Started: <ts>
- Completed: <ts>
- Wall clock: <duration>
- Evidence: <list with sha256>
- Model: <model_id>
- Tool versions: <yaml>

## Findings Summary
- Confirmed: N
- Inferred: N
- Uncertain: N
- Unknown / gaps acknowledged: N

## Confusion Matrix
| | Threat (truth) | Benign (truth) |
|---|---|---|
| Threat (agent) | <TP> | <FP> |
| Benign (agent) | <FN> | <TN> |

Precision: <%>  | Recall: <%>  | F1: <%>

## Hallucinations
<count> caught. List with finding_id, mechanism, resolution.

## Hallucination Corpus Result
- clean-001.dmp: 0 findings ✓
- clean-002.img: 0 findings ✓
- clean-003.tar: 0 findings ✓

## Acknowledged Gaps
<count> total. Examples:
- "<scope>" — <reason>

## Self-Corrections
<count> total. Examples:
- finding_id <X>: original "<...>" → corrected "<...>" — verifier caught <delta>

## Tool Failures
<count>. Each handled by <gap_acknowledged | alternative tool | retry>.

## Cost
- Tokens in: <N>
- Tokens out: <N>
- Estimated cost: $<X>

## Reproducibility
- Run via: `./scripts/replay.sh <CASE_ID>`
- Drift envelope: ≤<N> findings between runs on identical evidence
- Stochastic surfaces: LLM sampling at temperature <T>, otherwise deterministic
```

## Scoring Logic For Self-Assessment

| Behavior | Score Direction |
|---|---|
| High TP rate | + |
| Low FP rate | + |
| Acknowledged gaps documented | + |
| Self-corrections present | + |
| Honest reporting of FNs and tool failures | + |
| Inflated claims (TP without verifier) | − |
| Hidden failures | − |
| Hallucinations not caught | − |

The point is to be the team that judges trust, not the team with the prettiest claims.
