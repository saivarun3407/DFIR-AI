#!/usr/bin/env python3
"""Diff agent findings against ground truth, emit confusion matrix.

Used by replay.sh + eval.sh during W6 accuracy testing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text())


def normalize_id(finding: dict) -> str:
    return finding.get("ground_truth_id") or finding.get("finding_id") or finding.get("claim", "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--actual", required=True, type=Path)
    ap.add_argument("--truth", required=True, type=Path)
    args = ap.parse_args()

    actual = load(args.actual)
    truth = load(args.truth)

    truth_ids = {normalize_id(t) for t in truth}
    actual_ids = {normalize_id(a) for a in actual}

    tp = truth_ids & actual_ids
    fp = actual_ids - truth_ids
    fn = truth_ids - actual_ids

    print(f"TP={len(tp)} FP={len(fp)} FN={len(fn)}")
    print(f"Precision: {len(tp) / max(1, len(tp) + len(fp)):.2%}")
    print(f"Recall:    {len(tp) / max(1, len(tp) + len(fn)):.2%}")

    return 0 if len(fp) == 0 and len(fn) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
