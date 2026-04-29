# Evidence Dataset Documentation

## Required Hackathon Deliverable

Per FIND EVIL! rules:
> Evidence Dataset Documentation (what tested, source, findings)

## Public Corpora Used

### Windows

| Corpus | Source | Ground Truth | License |
|---|---|---|---|
| DFRWS 2008 Memory Challenge | dfrws.org | Public scenario writeup | Public domain |
| Volatility Foundation samples (Cridex, Stuxnet, Zeus) | volatilityfoundation.org/samples | Annotations | Public |
| NIST CFReDS — Hacking Case | cfreds.nist.gov | NIST scenario doc | Public |

### macOS

| Corpus | Source | Ground Truth | License |
|---|---|---|---|
| TBD W3 — sample APFS image w/ known malware | (to source) | (to author) | (TBD) |
| TBD W3 — iOS backup w/ known apps | (to source) | (to author) | (TBD) |

### Linux

| Corpus | Source | Ground Truth | License |
|---|---|---|---|
| TBD W4 — SSH compromise scenario | (to source) | (to author) | (TBD) |
| TBD W4 — container escape | (to source) | (to author) | (TBD) |

### Hallucination Corpus (clean baselines)

3 deliberately clean dumps. Agent must produce **zero findings** on these. Used to measure hallucination rate.

| Corpus | Description | Expected Findings |
|---|---|---|
| `clean-001` | Idle Win10 VM memory snapshot | 0 |
| `clean-002` | Stock Ubuntu 22.04 disk image | 0 |
| `clean-003` | Default macOS install, no apps used | 0 |

## Per-Case Layout

```
corpus/
├── README.md
├── _template/
│   ├── ground-truth.json
│   └── README.md
├── dfrws-2008-memory/
│   ├── memory.dmp                  (gitignored — drop your own copy)
│   ├── ground-truth.json
│   └── README.md
├── volatility-cridex/
├── volatility-zeus/
├── nist-hacking-case/
└── clean-001/

# Local-only policy: nothing in this repo downloads evidence at runtime.
# Drop your own evidence into cases/<id>/input/ or run `mh self-collect`
# to populate from the host machine.
```

## ground-truth.json Schema

```json
{
  "case_id": "dfrws-2008-memory",
  "description": "...",
  "source_url": "https://...",
  "expected_findings": [
    {
      "ground_truth_id": "GT-001",
      "claim": "Process injection in <process>",
      "evidence_hint": "windows.malfind on PID <X>",
      "mitre_attck": ["T1055"]
    }
  ],
  "expected_hallucinations": 0
}
```
