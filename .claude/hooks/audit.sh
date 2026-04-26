#!/usr/bin/env bash
# PostToolUse hook — append every tool call to the hash-chained audit log.
# Captures: tool, args, result hash, tokens (if available), latency.
set -euo pipefail

INPUT_JSON=$(cat)

OUTPUT_DIR="${OUTPUT_PATH:-${CLAUDE_PROJECT_DIR}/output}"
CHAIN_LOG="$OUTPUT_DIR/chain-of-custody.jsonl"

python3 -m protocol_sift_mcp.tools.evidence chain_append \
    --chain "$CHAIN_LOG" \
    --event "tool_call" \
    --data "$INPUT_JSON" || {
    echo "{\"hookSpecificOutput\": {\"hookEventName\": \"PostToolUse\", \"additionalContext\": \"chain append failed (non-fatal)\"}}"
    exit 0
}

echo '{"hookSpecificOutput": {"hookEventName": "PostToolUse"}}'
