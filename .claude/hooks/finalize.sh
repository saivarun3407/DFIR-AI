#!/usr/bin/env bash
# Stop hook — verify chain integrity, generate signed attestation, finalize reports.
set -euo pipefail

OUTPUT_DIR="${OUTPUT_PATH:-${CLAUDE_PROJECT_DIR}/output}"
CHAIN_LOG="$OUTPUT_DIR/chain-of-custody.jsonl"
CASE_ID="${CASE_ID:-unknown}"

if ! python3 -m protocol_sift_mcp.tools.evidence chain_verify --chain "$CHAIN_LOG"; then
    touch "$OUTPUT_DIR/chain_invalid.flag"
    echo "{\"hookSpecificOutput\": {\"hookEventName\": \"Stop\", \"additionalContext\": \"CHAIN INVALID — refusing to sign attestation. See $OUTPUT_DIR/chain_invalid.flag\"}}"
    exit 0
fi

python3 -m protocol_sift_mcp.tools.evidence chain_append \
    --chain "$CHAIN_LOG" \
    --event "chain_finalize" \
    --data "{\"case_id\": \"${CASE_ID}\"}"

KEY_PATH="${SIGNING_KEY_PATH:-${CLAUDE_PROJECT_DIR}/keys/ed25519.priv}"
if [[ -f "$KEY_PATH" ]]; then
    python3 -m protocol_sift_mcp.tools.evidence attest \
        --chain "$CHAIN_LOG" \
        --findings "$OUTPUT_DIR/findings.json" \
        --case-id "$CASE_ID" \
        --key "$KEY_PATH" \
        --output "$OUTPUT_DIR/case-${CASE_ID}.attestation.json"
fi

echo "{\"hookSpecificOutput\": {\"hookEventName\": \"Stop\", \"additionalContext\": \"chain verified, attestation written to $OUTPUT_DIR/case-${CASE_ID}.attestation.json\"}}"
