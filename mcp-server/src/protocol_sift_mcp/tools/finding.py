"""finding_record — schema-enforced finding registration.

Rejects un-pinned claims at the API boundary. The whole trust stack collapses
without this gate.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..schema import Finding


def finding_record(findings_path: Path, finding: dict) -> dict:
    """Validate against schema, append to findings.json (JSON array file)."""
    parsed = Finding.model_validate(finding)

    findings_path.parent.mkdir(parents=True, exist_ok=True)
    if findings_path.exists() and findings_path.stat().st_size > 0:
        existing = json.loads(findings_path.read_text())
        if not isinstance(existing, list):
            raise RuntimeError(f"{findings_path} is not a JSON array")
    else:
        existing = []

    record = parsed.model_dump(mode="json")
    record["recorded_at"] = datetime.now(timezone.utc).isoformat()
    existing.append(record)
    findings_path.write_text(json.dumps(existing, indent=2, default=str))
    return record


def list_findings(findings_path: Path) -> list[dict]:
    if not findings_path.exists():
        return []
    return json.loads(findings_path.read_text())
