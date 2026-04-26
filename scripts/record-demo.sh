#!/usr/bin/env bash
# Demo recording wrapper. asciinema for terminal; OBS for video w/ audio.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$PROJECT_DIR/docs/demo"
mkdir -p "$OUT_DIR"

NAME="${1:-demo-$(date -u +%Y%m%d-%H%M%S)}"

if ! command -v asciinema >/dev/null 2>&1; then
    echo "asciinema not installed. apt-get install asciinema or brew install asciinema"
    exit 1
fi

echo ">> Recording asciinema cast to $OUT_DIR/$NAME.cast"
asciinema rec --idle-time-limit 2 "$OUT_DIR/$NAME.cast"
echo ">> Done. Convert to gif: agg $OUT_DIR/$NAME.cast $OUT_DIR/$NAME.gif"
