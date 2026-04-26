# Usage

## Prereqs

- SANS SIFT Workstation OVA (Ubuntu 22.04-based VM)
- Docker + docker compose
- Python 3.11
- Anthropic API key

## First-Time Setup

```bash
git clone <repo>
cd memory-hound
./scripts/install.sh
docker compose build
```

## Running A Case

```bash
mkdir -p input output
cp /path/to/evidence/* input/

export ANTHROPIC_API_KEY="sk-ant-..."
export CASE_ID=case-001
docker compose up
```

Watch for output in `output/`:
- `chain-of-custody.jsonl` — append-only audit log (tamper-evident)
- `findings.json` — structured findings, every one pinned
- `narrative.md` — investigator-ready prose
- `accuracy-report.md` — honest FP/FN/hallucination tally
- `case-<id>.attestation.json` — signed attestation

## Verifying A Run

```bash
python3 -m protocol_sift_mcp.tools.evidence chain_verify \
    --chain output/chain-of-custody.jsonl

# Verify attestation signature
python3 scripts/verify_attestation.py \
    --attestation output/case-001.attestation.json \
    --pubkey keys/ed25519.pub
```

## Live Tamper Demo

For the demo video:

```bash
# 1. Show clean chain
python3 -m protocol_sift_mcp.tools.evidence chain_verify --chain output/chain-of-custody.jsonl
# ✓ Chain valid

# 2. Tamper one entry
sed -i 's/"confidence":"inferred"/"confidence":"confirmed"/' output/chain-of-custody.jsonl

# 3. Re-verify — fails immediately
python3 -m protocol_sift_mcp.tools.evidence chain_verify --chain output/chain-of-custody.jsonl
# ✗ hash mismatch at line N
```

## Replay (Reproducibility)

```bash
./scripts/replay.sh dfrws-2008-memory
# Re-runs the exact same case, diffs against ground truth.
```
