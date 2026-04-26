"""Trust-stack core: hash chain, signing, attestations.

This is the most important module in MemoryHound. It is the mechanism that
makes findings provable. Tests live in ``tests/test_evidence.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from ..sandbox import assert_input_path

GENESIS_HASH = "GENESIS"
HASH_ALGO = "sha256"


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha1_hex(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()  # noqa: S324 — dual-hash for collision resistance, not crypto-only reliance


def _entry_hash(seq: int, prev_hash: str, ts: str, event: str, data: dict) -> str:
    payload = f"{seq}||{prev_hash}||{ts}||{event}||{_canonical_json(data)}"
    return _sha256_hex(payload.encode("utf-8"))


def hash_file(path: Path, *, chunk_size: int = 1 << 20) -> dict[str, str | int]:
    """Compute sha256 + sha1 of a file in one pass."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()  # noqa: S324
    size = 0
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
            sha1.update(chunk)
            size += len(chunk)
    return {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest(), "size": size}


def chain_init(
    chain_path: Path,
    *,
    case_id: str,
    evidence_path: str,
    agent_version: str,
    model: str,
) -> dict:
    """Write the genesis entry. Idempotent: returns existing genesis if file exists."""
    if chain_path.exists() and chain_path.stat().st_size > 0:
        with chain_path.open() as f:
            return json.loads(f.readline())

    ts = datetime.now(UTC).isoformat()
    data = {
        "case_id": case_id,
        "evidence_path": evidence_path,
        "agent_version": agent_version,
        "model": model,
    }
    entry = {
        "seq": 0,
        "prev_hash": GENESIS_HASH,
        "ts": ts,
        "event": "chain_init",
        "data": data,
        "hash": _entry_hash(0, GENESIS_HASH, ts, "chain_init", data),
    }
    chain_path.parent.mkdir(parents=True, exist_ok=True)
    with chain_path.open("w") as f:
        f.write(_canonical_json(entry) + "\n")
    return entry


def chain_append(chain_path: Path, *, event: str, data: dict) -> dict:
    """Append a new entry. Computes seq + prev_hash from existing tail."""
    if not chain_path.exists():
        raise RuntimeError(
            f"Chain log not initialized at {chain_path}. Call chain_init first."
        )

    last_entry: dict | None = None
    with chain_path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                last_entry = json.loads(line)
    if last_entry is None:
        raise RuntimeError(f"Chain log at {chain_path} is empty.")

    seq = last_entry["seq"] + 1
    prev_hash = last_entry["hash"]
    ts = datetime.now(UTC).isoformat()
    entry = {
        "seq": seq,
        "prev_hash": prev_hash,
        "ts": ts,
        "event": event,
        "data": data,
        "hash": _entry_hash(seq, prev_hash, ts, event, data),
    }
    with chain_path.open("a") as f:
        f.write(_canonical_json(entry) + "\n")
    return entry


def chain_verify(chain_path: Path) -> tuple[bool, list[str]]:
    """Re-compute every entry hash and verify the chain link.

    Returns (ok, problems) where problems is a list of human-readable issues.
    """
    problems: list[str] = []
    expected_prev = GENESIS_HASH
    expected_seq = 0

    if not chain_path.exists():
        return False, [f"Chain log not found at {chain_path}"]

    with chain_path.open() as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                problems.append(f"line {line_num}: invalid JSON: {exc}")
                return False, problems

            if entry.get("seq") != expected_seq:
                problems.append(
                    f"seq={entry.get('seq')} at line {line_num}: expected {expected_seq}"
                )
                return False, problems
            if entry.get("prev_hash") != expected_prev:
                got = entry.get("prev_hash")
                problems.append(
                    f"line {line_num} seq={expected_seq}: prev_hash mismatch "
                    f"(expected {expected_prev}, got {got})"
                )
                return False, problems

            recomputed = _entry_hash(
                entry["seq"],
                entry["prev_hash"],
                entry["ts"],
                entry["event"],
                entry["data"],
            )
            if recomputed != entry.get("hash"):
                stored = entry.get("hash")
                problems.append(
                    f"line {line_num} seq={expected_seq}: hash mismatch "
                    f"(recomputed {recomputed}, stored {stored})"
                )
                return False, problems

            expected_prev = entry["hash"]
            expected_seq += 1

    return True, []


def sign_findings(findings_path: Path, key_path: Path) -> bytes:
    """Produce ed25519 signature over canonical JSON of findings."""
    with key_path.open("rb") as f:
        priv = load_pem_private_key(f.read(), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise TypeError(f"Key at {key_path} is not ed25519")
    with findings_path.open("rb") as f:
        body = f.read()
    return priv.sign(body)


def generate_keypair(out_dir: Path) -> tuple[Path, Path]:
    """Generate ed25519 keypair, write priv (PEM) + pub (raw)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )
    priv_path = out_dir / "ed25519.priv"
    pub_path = out_dir / "ed25519.pub"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_raw)
    priv_path.chmod(0o600)
    return priv_path, pub_path


def attest(
    *,
    chain_path: Path,
    findings_path: Path,
    case_id: str,
    key_path: Path,
    output_path: Path,
    agent_version: str = "memoryhound@0.1.0",
    model: str = "claude-opus-4-7",
) -> dict:
    """Generate SLSA-style attestation tying chain + findings + signature."""
    findings_hash = _sha256_hex(findings_path.read_bytes())
    last_chain_entry: dict | None = None
    with chain_path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                last_chain_entry = json.loads(line)
    if last_chain_entry is None:
        raise RuntimeError("Empty chain log; cannot attest.")
    chain_root_hash = last_chain_entry["hash"]
    signature = sign_findings(findings_path, key_path).hex()

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": f"case-{case_id}",
                "digest": {"sha256": findings_hash},
            }
        ],
        "predicateType": "https://memoryhound.dev/finding-attestation/v1",
        "predicate": {
            "agent": agent_version,
            "model": model,
            "case_id": case_id,
            "chain_root_hash": chain_root_hash,
            "completed_at": datetime.now(UTC).isoformat(),
            "signature_algorithm": "ed25519",
            "signature": signature,
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(statement))
    return statement


def ingest_artifact(chain_path: Path, artifact: Path) -> dict:
    """Hash an evidence file and append an evidence_ingest entry to the chain."""
    artifact = assert_input_path(artifact)
    digest = hash_file(artifact)
    return chain_append(
        chain_path,
        event="evidence_ingest",
        data={"artifact": str(artifact), **digest},
    )


def main(argv: list[str] | None = None) -> int:
    """CLI shim for hooks. Subcommands match what the bash scripts call."""
    parser = argparse.ArgumentParser(prog="protocol_sift_mcp.tools.evidence")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("chain_init")
    p_init.add_argument("--output", required=True, type=Path)
    p_init.add_argument("--case-id", required=True)
    p_init.add_argument("--evidence-path", required=True)
    p_init.add_argument("--agent-version", default="memoryhound@0.1.0")
    p_init.add_argument("--model", default="claude-opus-4-7")

    p_append = sub.add_parser("chain_append")
    p_append.add_argument("--chain", required=True, type=Path)
    p_append.add_argument("--event", required=True)
    p_append.add_argument("--data", required=True, help="JSON string")

    p_verify = sub.add_parser("chain_verify")
    p_verify.add_argument("--chain", required=True, type=Path)

    p_ingest = sub.add_parser("ingest")
    p_ingest.add_argument("--chain", required=True, type=Path)
    p_ingest.add_argument("--artifact", required=True, type=Path)

    p_attest = sub.add_parser("attest")
    p_attest.add_argument("--chain", required=True, type=Path)
    p_attest.add_argument("--findings", required=True, type=Path)
    p_attest.add_argument("--case-id", required=True)
    p_attest.add_argument("--key", required=True, type=Path)
    p_attest.add_argument("--output", required=True, type=Path)

    p_keys = sub.add_parser("keygen")
    p_keys.add_argument("--out-dir", required=True, type=Path)

    args = parser.parse_args(argv)

    if args.cmd == "chain_init":
        chain_init(
            args.output,
            case_id=args.case_id,
            evidence_path=args.evidence_path,
            agent_version=args.agent_version,
            model=args.model,
        )
        print(f"chain initialized: {args.output}")
        return 0
    if args.cmd == "chain_append":
        chain_append(args.chain, event=args.event, data=json.loads(args.data))
        return 0
    if args.cmd == "chain_verify":
        ok, problems = chain_verify(args.chain)
        if ok:
            print(f"✓ Chain valid: {args.chain}")
            return 0
        for p in problems:
            print(f"✗ {p}", file=sys.stderr)
        return 1
    if args.cmd == "ingest":
        ingest_artifact(args.chain, args.artifact)
        return 0
    if args.cmd == "attest":
        attest(
            chain_path=args.chain,
            findings_path=args.findings,
            case_id=args.case_id,
            key_path=args.key,
            output_path=args.output,
        )
        print(f"attestation written: {args.output}")
        return 0
    if args.cmd == "keygen":
        priv, pub = generate_keypair(args.out_dir)
        print(f"private key: {priv}")
        print(f"public key:  {pub}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
