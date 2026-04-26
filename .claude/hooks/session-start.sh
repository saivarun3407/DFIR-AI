#!/usr/bin/env bash
# SessionStart hook — initialize the chain of custody and hash all input evidence
# before any agent action runs.
set -euo pipefail

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
OUTPUT_DIR="${OUTPUT_PATH:-${PROJECT_DIR}/output}"
INPUT_DIR="${EVIDENCE_PATH:-${PROJECT_DIR}/input}"
CASE_ID="${CASE_ID:-default-$(date -u +%Y%m%d%H%M%S)}"

mkdir -p "$OUTPUT_DIR"
CHAIN_LOG="$OUTPUT_DIR/chain-of-custody.jsonl"

if [[ ! -f "$CHAIN_LOG" ]]; then
    python3 -m protocol_sift_mcp.tools.evidence chain_init \
        --output "$CHAIN_LOG" \
        --case-id "$CASE_ID" \
        --evidence-path "$INPUT_DIR" \
        --agent-version "memoryhound@0.1.0" \
        --model "${MODEL_NAME:-claude-opus-4-7}"
fi

if [[ -d "$INPUT_DIR" ]]; then
    while IFS= read -r -d '' artifact; do
        python3 -m protocol_sift_mcp.tools.evidence ingest \
            --chain "$CHAIN_LOG" \
            --artifact "$artifact"
    done < <(find "$INPUT_DIR" -type f -print0)
fi

echo "{\"hookSpecificOutput\": {\"hookEventName\": \"SessionStart\", \"additionalContext\": \"chain initialized at $CHAIN_LOG, case=$CASE_ID\"}}"
