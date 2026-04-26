---
name: memory-forensics
description: Cross-OS memory analysis using Volatility 3. Use when a memory dump (raw, AFF, EWF, LiME) is provided. Encodes Memory Forensics Cheat Sheet v2.1 and Rekall acquisition guidance.
---

# Memory Forensics

Reference: SANS DFIR Cheat Sheet Memory Forensics v2.1 (pp. 36-37) + Rekall pp. 38-40.

## Sequencing (apply per OS)

### Windows
1. `windows.info` → kernel build, layout, profile
2. `windows.pslist` + `windows.psscan` + `windows.pstree` → process universe; diff to spot hidden
3. `windows.cmdline` + `windows.envars` → invocation context
4. `windows.dlllist` + `windows.ldrmodules` → injected DLLs
5. `windows.malfind` → injected code regions
6. `windows.netscan` + `windows.netstat` → C2
7. `windows.handles` + `windows.filescan` + `windows.mutantscan` → IOCs
8. `windows.svcscan` → suspicious services
9. `windows.registry.printkey` for AutoStart, ImageFileExecutionOptions, etc.
10. `windows.timeliner` → timeline integration

### macOS
1. `mac.list_files`
2. `mac.pslist` + `mac.psscan` + `mac.psaux`
3. `mac.lsof`
4. `mac.malfind`
5. `mac.netstat`
6. `mac.dyld_inserted_libraries`
7. `mac.kextstat`

### Linux
1. `linux.pslist` + `linux.pstree` + `linux.psaux` + `linux.psscan`
2. `linux.bash` (recover bash history from memory)
3. `linux.lsof`
4. `linux.malfind`
5. `linux.sockstat`
6. `linux.iomem`
7. `linux.elfs`
8. `linux.check_modules` + `linux.lsmod` (rootkit indicator)

## High-Confidence Pin Format

```json
{
  "artifact": "memory.dmp",
  "tool": "windows.malfind",
  "pid": 4216,
  "process_name": "explorer.exe",
  "vad_start": "0x7ff812340000",
  "vad_end": "0x7ff812350000",
  "protection": "PAGE_EXECUTE_READWRITE",
  "first_bytes_hex": "4d5a90000300000004000000ffff0000",
  "raw_excerpt": "..."
}
```

## Confirmation Patterns

- Process injection: `malfind` hit + `ldrmodules` orphan + `handles` to suspicious DLL = `confirmed`
- C2 connection: `netscan` socket + matching process in `pslist` + `cmdline` containing exec args = `confirmed`
- Hidden process: in `psscan` but not `pslist` (or `pstree`) = `confirmed` (DKOM rootkit indicator)

## Anti-Hallucination Rules

- Do NOT report a process as "malicious" without an explicit IOC (signature match, hash match, anomalous behavior chain). Suspicious ≠ malicious.
- If `malfind` hits but the region is benign (signed mapped image, JIT), tag as `uncertain` not `confirmed`.
- Symbol table problems: if Volatility errors with "no profile" or "broken layer", record as `event:tool_failure`. Do not invent findings to fill the gap.
