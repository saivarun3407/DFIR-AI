# Evidence Corpus

This directory holds DFIR evidence used for testing and evaluation. **Evidence files themselves are gitignored** — only `ground-truth.json` and per-case READMEs are committed.

## Layout

```
corpus/
├── _template/
│   ├── ground-truth.json
│   └── README.md
├── <case-id>/
│   ├── *.dmp / *.img / *.E01    (gitignored)
│   ├── ground-truth.json
│   └── README.md
```

## Sourcing Evidence

Run per-case `download.sh` (when present) to fetch from the public corpus host. Verify sha256 after download.

## Cases

To be populated W2-W4 of implementation plan:

- `dfrws-2008-memory` (Windows)
- `volatility-cridex` (Windows)
- `volatility-zeus` (Windows)
- `nist-hacking-case` (Windows)
- TBD macOS (W3)
- TBD Linux (W4)
- `clean-001`, `clean-002`, `clean-003` (hallucination corpus)
