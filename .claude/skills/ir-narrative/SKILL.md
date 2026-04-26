---
name: ir-narrative
description: Convert structured verified findings into investigative prose suitable for an IR analyst report. Output is a structured narrative, not a raw execution log — required by hackathon rules.
---

# IR Narrative

Hackathon rules require: "output is presented as a structured investigative narrative, not a raw execution log."

## Required Structure

```markdown
# Incident Report — Case <CASE_ID>

## Executive Summary
2-3 sentences. What happened, severity, key actors/targets.

## Timeline of Events
Reverse chronological. Each entry:
- **<timestamp UTC>** — <plain language description> [pin: <finding_id>]

## Threat Actor Behavior
What did they do, in narrative form. Group findings by attacker phase:
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command & Control
- Exfiltration
- Impact

(MITRE ATT&CK alignment — only assert TTPs that pin to specific findings.)

## Indicators of Compromise (IOCs)
- File hashes
- IPs / domains
- Process names + cmdlines
- Persistence locations

## Confidence Map
For each section, how certain we are and why.

## Gaps + Recommendations
What we don't know, and what evidence would resolve it.
```

## Discipline

- Every assertion in prose MUST link back to a `finding_id` in brackets — `[F-042]`
- Use plain language; assume reader is a senior IR analyst not a debugger
- Refer to confidence enum without quoting it: "execution is confirmed by Prefetch and BAM" not "confirmed: yes"
- Do NOT invent intent. "Process X connected to Y" is a fact. "Attacker exfiltrated data via X" is an interpretation; only state it if evidence supports it.

## Length

Aim 1-3 pages. Long-form prose loses judges. Tight, evidenced, structured wins.
