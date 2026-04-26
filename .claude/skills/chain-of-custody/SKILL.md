---
name: chain-of-custody
description: Tamper-evident hash-chained JSONL audit log. Every event is sealed by sha256(seq || prev_hash || ts || event || data). Edits break the chain — instant tamper detection. Encodes the Accountability + Authenticity layers of the trust stack.
---

# Chain of Custody

## The Chain

`chain-of-custody.jsonl` is append-only and hash-linked. Every entry sealed:

```
hash_n = sha256(seq_n || prev_hash_n || ts_n || event_n || canonical_json(data_n))
```

Where `prev_hash_0 = "GENESIS"`.

## Genesis Entry

Written by `SessionStart` hook:

```json
{
  "seq": 0,
  "prev_hash": "GENESIS",
  "ts": "2026-04-25T22:00:00Z",
  "event": "chain_init",
  "data": {
    "case_id": "demo-001",
    "evidence_path": "/input",
    "agent_version": "memoryhound@0.1.0",
    "model": "claude-opus-4-7",
    "tool_versions": {
      "volatility3": "2.7.0",
      "plaso": "20240825",
      "sleuthkit": "4.12.1"
    }
  },
  "hash": "<computed>"
}
```

## Mandatory Events

Every one of these MUST appear in the chain:

| Event | When | Required Fields |
|---|---|---|
| `chain_init` | session start | case_id, evidence_path, versions |
| `evidence_ingest` | per artifact | artifact, sha256, sha1, size |
| `tool_call` | every MCP call | tool, args, result_hash, tokens_in, tokens_out, latency_ms |
| `finding_recorded` | each finding | finding_id, claim, confidence, pins |
| `verifier_result` | each verify | finding_id, decision, delta |
| `self_correction` | each revision | finding_id, original, corrected, reason |
| `gap_acknowledged` | each "I don't know" | scope, reason |
| `tool_failure` | every error | tool, error_class, error_msg |
| `chain_finalize` | session stop | findings_count, attestation_path |

## Invariants Enforced By MCP Server

1. **Append-only** — `chain_append` is the only write path. No update/delete API.
2. **Sequential** — `seq` strictly monotonic from 0.
3. **Linked** — every entry's `prev_hash` MUST match the previous entry's `hash`. Mismatch = chain broken.
4. **Verifiable** — `verify_chain(path)` recomputes every hash and reports first divergence.

## Live Tamper Demo

In the hackathon demo video, do this:

```bash
# show the chain is valid
$ python -m protocol_sift_mcp.tools.evidence verify_chain /output/chain-of-custody.jsonl
✓ Chain valid: 247 entries, all hashes match

# tamper one finding
$ jq '.[] | select(.seq==42) | .data.confidence="confirmed"' chain-of-custody.jsonl > tampered.jsonl
$ python -m protocol_sift_mcp.tools.evidence verify_chain tampered.jsonl
✗ Chain broken at seq=42: hash mismatch (recomputed: a3f1..., stored: 8b2e...)
```

This is the single most powerful 15 seconds of the demo video.

## When To Write A Chain Entry

You don't write chain entries directly. The `PostToolUse` hook writes them automatically after every MCP call. The only manual write is `gap_acknowledged` — call `mcp__protocol_sift__chain_acknowledge_gap(scope, reason)` whenever you intentionally choose not to make a claim.

Acknowledged gaps are scored POSITIVELY in the accuracy report — judges interpret them as honesty discipline.
