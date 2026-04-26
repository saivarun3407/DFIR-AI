"""Trust-stack tests. Hash chain MUST be tamper-evident; signing MUST verify; sandbox MUST reject path escapes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)

from protocol_sift_mcp.tools import evidence as ev


def test_hash_file_dual_algorithm(tmp_path: Path) -> None:
    f = tmp_path / "input" / "sample.bin"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(b"the quick brown fox jumps over the lazy dog")
    digest = ev.hash_file(f)
    assert digest["sha256"] == "05c6e08f1d9fdafa03147fcb8f82f124c76d2f70e3d989dc8aadb5e7d7450bec"
    assert digest["sha1"] == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
    assert digest["size"] == 43


def test_chain_init_idempotent(tmp_path: Path) -> None:
    chain = tmp_path / "output" / "chain.jsonl"
    first = ev.chain_init(
        chain,
        case_id="t-1",
        evidence_path=str(tmp_path / "input"),
        agent_version="memoryhound@test",
        model="claude-test",
    )
    second = ev.chain_init(
        chain,
        case_id="t-1",
        evidence_path=str(tmp_path / "input"),
        agent_version="memoryhound@test",
        model="claude-test",
    )
    assert first["seq"] == 0
    assert first == second


def test_chain_append_links_correctly(tmp_path: Path) -> None:
    chain = tmp_path / "output" / "chain.jsonl"
    ev.chain_init(
        chain,
        case_id="t-1",
        evidence_path=str(tmp_path / "input"),
        agent_version="memoryhound@test",
        model="claude-test",
    )
    e1 = ev.chain_append(chain, event="tool_call", data={"tool": "fake_a"})
    e2 = ev.chain_append(chain, event="tool_call", data={"tool": "fake_b"})

    assert e1["seq"] == 1
    assert e2["seq"] == 2
    assert e2["prev_hash"] == e1["hash"]


def test_chain_verify_passes_on_clean_chain(tmp_path: Path) -> None:
    chain = tmp_path / "output" / "chain.jsonl"
    ev.chain_init(
        chain,
        case_id="t-1",
        evidence_path=str(tmp_path / "input"),
        agent_version="memoryhound@test",
        model="claude-test",
    )
    for i in range(5):
        ev.chain_append(chain, event="tool_call", data={"i": i})
    ok, problems = ev.chain_verify(chain)
    assert ok, problems


def test_chain_verify_detects_data_tamper(tmp_path: Path) -> None:
    chain = tmp_path / "output" / "chain.jsonl"
    ev.chain_init(
        chain,
        case_id="t-1",
        evidence_path=str(tmp_path / "input"),
        agent_version="memoryhound@test",
        model="claude-test",
    )
    for i in range(3):
        ev.chain_append(chain, event="tool_call", data={"i": i})

    lines = chain.read_text().strip().split("\n")
    entry = json.loads(lines[2])
    entry["data"]["i"] = 999
    lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    chain.write_text("\n".join(lines) + "\n")

    ok, problems = ev.chain_verify(chain)
    assert not ok
    assert any("hash mismatch" in p for p in problems)


def test_chain_verify_detects_link_break(tmp_path: Path) -> None:
    chain = tmp_path / "output" / "chain.jsonl"
    ev.chain_init(
        chain,
        case_id="t-1",
        evidence_path=str(tmp_path / "input"),
        agent_version="memoryhound@test",
        model="claude-test",
    )
    ev.chain_append(chain, event="tool_call", data={"i": 0})
    ev.chain_append(chain, event="tool_call", data={"i": 1})

    lines = chain.read_text().strip().split("\n")
    entry = json.loads(lines[1])
    entry["prev_hash"] = "0" * 64
    lines[1] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    chain.write_text("\n".join(lines) + "\n")

    ok, problems = ev.chain_verify(chain)
    assert not ok
    assert any("prev_hash mismatch" in p for p in problems)


def test_chain_verify_detects_seq_skip(tmp_path: Path) -> None:
    chain = tmp_path / "output" / "chain.jsonl"
    ev.chain_init(
        chain,
        case_id="t-1",
        evidence_path=str(tmp_path / "input"),
        agent_version="memoryhound@test",
        model="claude-test",
    )
    ev.chain_append(chain, event="tool_call", data={"i": 0})
    ev.chain_append(chain, event="tool_call", data={"i": 1})

    lines = chain.read_text().strip().split("\n")
    chain.write_text(lines[0] + "\n" + lines[2] + "\n")

    ok, problems = ev.chain_verify(chain)
    assert not ok


def test_keygen_and_sign_roundtrip(tmp_path: Path) -> None:
    priv_path, pub_path = ev.generate_keypair(tmp_path / "output" / "keys")
    findings = tmp_path / "output" / "findings.json"
    findings.write_text('[{"finding_id":"F-1","claim":"x","confidence":"inferred","pins":[]}]')

    sig = ev.sign_findings(findings, priv_path)
    assert len(sig) == 64

    pub_bytes = pub_path.read_bytes()
    pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    pub.verify(sig, findings.read_bytes())


def test_signature_fails_on_tamper(tmp_path: Path) -> None:
    priv_path, pub_path = ev.generate_keypair(tmp_path / "output" / "keys")
    findings = tmp_path / "output" / "findings.json"
    findings.write_text('[{"finding_id":"F-1"}]')
    sig = ev.sign_findings(findings, priv_path)

    findings.write_text('[{"finding_id":"F-2"}]')

    pub = Ed25519PublicKey.from_public_bytes(pub_path.read_bytes())
    with pytest.raises(Exception):
        pub.verify(sig, findings.read_bytes())


def test_attest_writes_in_toto_statement(tmp_path: Path) -> None:
    chain = tmp_path / "output" / "chain.jsonl"
    findings = tmp_path / "output" / "findings.json"
    findings.write_text("[]")
    priv_path, _ = ev.generate_keypair(tmp_path / "output" / "keys")
    ev.chain_init(
        chain,
        case_id="t-1",
        evidence_path=str(tmp_path / "input"),
        agent_version="memoryhound@test",
        model="claude-test",
    )

    out = tmp_path / "output" / "case-t-1.attestation.json"
    statement = ev.attest(
        chain_path=chain,
        findings_path=findings,
        case_id="t-1",
        key_path=priv_path,
        output_path=out,
    )
    assert statement["_type"].startswith("https://in-toto.io")
    assert statement["subject"][0]["name"] == "case-t-1"
    assert "signature" in statement["predicate"]
    assert out.exists()


def test_finding_record_rejects_empty_pins(tmp_path: Path) -> None:
    from protocol_sift_mcp.tools import finding as fd

    findings = tmp_path / "output" / "findings.json"
    bad = {
        "finding_id": "F-1",
        "claim": "test",
        "confidence": "inferred",
        "pins": [],
    }
    with pytest.raises(Exception):
        fd.finding_record(findings, bad)


def test_finding_record_accepts_valid_pin(tmp_path: Path) -> None:
    from protocol_sift_mcp.tools import finding as fd

    findings = tmp_path / "output" / "findings.json"
    good = {
        "finding_id": "F-1",
        "claim": "test claim",
        "confidence": "inferred",
        "pins": [
            {
                "artifact": "memory.dmp",
                "tool": "windows.pslist",
                "locator": {"type": "memory_vad", "value": "pid=1234 vad=0x100"},
                "raw_excerpt": "deadbeef",
                "captured_at": "2026-04-25T22:00:00Z",
            }
        ],
    }
    record = fd.finding_record(findings, good)
    assert record["finding_id"] == "F-1"
    assert findings.exists()
