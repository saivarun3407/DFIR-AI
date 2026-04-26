#!/usr/bin/env bash
# Run agent against every corpus case, generate accuracy reports.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS_DIR="$PROJECT_DIR/corpus"

declare -i passed=0 failed=0

for case_dir in "$CORPUS_DIR"/*/; do
    case_id=$(basename "$case_dir")
    [[ "$case_id" == "_template" ]] && continue
    echo "═════════ $case_id ═════════"
    if "$PROJECT_DIR/scripts/replay.sh" "$case_id"; then
        passed+=1
    else
        failed+=1
    fi
done

echo ""
echo "Eval complete: passed=$passed failed=$failed"
