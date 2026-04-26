---
name: gap-acknowledgment
description: Discipline for acknowledging what we don't know. Calling `chain_acknowledge_gap` is a strength signal — judges score honesty positively and detect inflated claims fast. This skill teaches when to refuse vs. when to assert.
---

# Gap Acknowledgment

"I don't know" is a valid output. Use it.

## When To Call `chain_acknowledge_gap`

| Situation | Action |
|---|---|
| Tool failed with no fallback that produces same evidence class | acknowledge + note alternative attempted |
| Symbol table missing for memory dump | acknowledge — do NOT invent process names |
| Encrypted artifact (Signal DB without keychain access) | acknowledge — do NOT speculate on contents |
| Evidence corrupted / partial | acknowledge — note recoverable vs unrecoverable |
| Single ambiguous artifact, not enough to pin confidence higher than `uncertain` | EITHER pin as `uncertain` OR acknowledge gap, not both |
| Question outside scope (e.g., asked about Linux when only Windows evidence ingested) | acknowledge — do NOT extrapolate |

## When NOT To Acknowledge

- Don't flood the chain with trivial "couldn't determine X" entries — gaps should be substantive
- Don't acknowledge to dodge work; if the evidence is available, do the analysis

## Format

```python
mcp__protocol_sift__chain_acknowledge_gap(
    scope="cridex.exe network destinations",
    reason="netscan returned no entries for PID 1484; this could mean (a) connections were closed before snapshot, (b) memory was paged out, or (c) the process used a covert channel not visible to netscan. Insufficient evidence to choose."
)
```

The `reason` field is read by the accuracy-report skill and surfaced in the final report. Make it specific.

## Demo Value

Calling out 3-5 honest gaps in the demo video sets MemoryHound apart. Most teams will hide or paper over uncertainty. Judges notice.
