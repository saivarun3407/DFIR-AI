---
name: windows-triage
description: Windows DFIR artifact triage. Use when evidence is Windows 10/11 (registry hives, EVTX, prefetch, LNK, shellbags, browser, USB, cloud connectors). Encodes FOR500 v4.18 playbook.
---

# Windows Triage

You triage Windows evidence using the SANS FOR500 playbook. Every finding must cite a registry path, EVTX EID, file path, or memory offset.

## Investigation Order (priority)

### 1. Application Execution
Cross-reference these for high-confidence execution proof:
- **Shimcache** — `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` (Win7+, up to 1024 entries; tracks executable path + last modified, NOT proof of execution alone)
- **Amcache.hve** — `C:\Windows\AppCompat\Programs\Amcache.hve` (presence + SHA1 hash, NOT proof of execution alone)
- **Prefetch** — `C:\Windows\Prefetch\(exename)-(hash).pf` (Win8+: last 8 execution times, run count, file handles; this IS proof of execution)
- **BAM/DAM** — `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` (last execution date/time, ~1 week retention)
- **SRUM** — `C:\Windows\System32\SRU\SRUDB.dat` (ESE; tables `{973F5D5C}` Network, `{d10ca2fe}` App Resource, `{DD6636C4}` Network Connectivity; ~30-60 days, hourly batches)
- **UserAssist** — `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` (ROT-13 encoded; CEBFF5CD = exe execution, F4E57C4B = shortcut execution)
- **Win10 Timeline** — `C:\Users\<u>\AppData\Local\ConnectedDevicesPlatform\<account-ID>\ActivitiesCache.db` (SQLite, full path + start/end/duration)

**Confidence rule:** ≥2 of [Prefetch, BAM, UserAssist, SRUM, Win10 Timeline] aligning on path + time = `confirmed`. Single source = `inferred`. Shimcache or Amcache alone = `inferred` (presence, not execution).

### 2. Account / Authentication Activity
- **Security.evtx** EIDs to pull: `4624` (success logon, watch Type 10 = RDP), `4625` (failed logon), `4634/4647` (logoff), `4648` (runas explicit creds), `4672` (superuser logon), `4720` (account created), `4768/4769/4771` (Kerberos), `4776` (NTLM auth)
- **SAM hive** — `SAM\Domains\Account\Users\<RID>` for last login, password change, login count, group membership
- **ProfileList** — `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` for SID → username mapping

### 3. File / Folder Opening
- **LNK files** — `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\` (creation = first opened; last mod = last opened; internal data has target MACB, volume info, network share, system name)
- **JumpLists** — `\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` (per-app, ~2000 items, MRU-ordered with per-item timestamps)
- **RecentDocs** — `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` (last 150 rollup; per-extension subkeys)
- **ShellBags** — `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags` + `BagMRU` (massive folder access history including ZIP/mobile/control panel)
- **Office Recent** — `NTUSER.DAT\Software\Microsoft\Office\<Version>\<App>\File MRU` (16.0=2016/19/M365, 15.0=2013, 14.0=2010, 12.0=2007)

### 4. Deletion / Existence
- **Recycle Bin** — `C:\$Recycle.Bin\<SID>\$I######` (filename + deletion date), `$R######` (file contents)
- **Thumbcache** — `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\Thumbcache_*.db`
- **Windows Search DB** — `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` (ESE, partial content + 24hr gather logs)

### 5. Browser
- Chrome/Edge: `\AppData\Local\Google\Chrome\User Data\<Profile>\History` (visit_count, downloads, downloads_url_chains, keyword_search_terms)
- Firefox: `places.sqlite`, `formhistory.sqlite`, `cookies.sqlite`, `logins.json`
- HTML5 Web Storage / FileSystem: LevelDB

### 6. Cloud Connectors
- OneDrive: `NTUSER.DAT\Software\Microsoft\OneDrive\Accounts\<Personal|Business1>` + `SyncDiagnostics.log` + `<UserCid>.dat` + `.odl` logs
- Google Drive for Desktop: `NTUSER.DAT\Software\Google\DriveFS\Share\` + `\AppData\Local\Google\DriveFS\<account>\metadata_sqlite_db` (protobuf)
- Box Drive: `%USERPROFILE%\Box`, `\AppData\Local\Box\Box\cache`, `sync.db`, `streemsfs.db`
- Dropbox: `\Dropbox\.dropbox.cache`, `nucleus.sqlite3`, `sync_history.db`

### 7. Network
- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}` (NameType: 6=Wired, 23=VPN, 71=Wireless, 243=Mobile)
- `Microsoft-Windows-WLAN-AutoConfig/Operational.evtx` EIDs 11000, 8001, 8002, 8003, 6100

### 8. USB
- `SYSTEM\CurrentControlSet\Enum\USBSTOR` + `USB` + `SCSI` + `HID`
- `SYSTEM\MountedDevices` + `NTUSER.DAT\...\MountPoints2`
- Connection times: `setupapi.dev.log` and `Properties\{83da6326-...}\0064` (First Install) / `0066` (Last Connected) / `0067` (Last Removal)
- Win10+: `Microsoft-Windows-Partition/Diagnostic.evtx` EID 1006 (device connect/disconnect, VBR data)

## MCP Tools Available

- `mcp__protocol_sift__win_registry_get(hive, path)` → typed values
- `mcp__protocol_sift__win_evtx_query(log, eid, time_range)` → events
- `mcp__protocol_sift__win_prefetch_parse(path)` → exec history
- `mcp__protocol_sift__win_lnk_parse(path)` → shellitem details
- `mcp__protocol_sift__win_shellbag_parse(hive)` → folder access
- `mcp__protocol_sift__win_recyclebin_parse(path)` → deleted files
- `mcp__protocol_sift__win_ese_query(db_path, table, query)` → ESE row results

## Pin Format

```json
{
  "artifact": "NTUSER.DAT",
  "tool": "win_registry_get",
  "path": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-...}\\Count",
  "value_name": "...",
  "raw_excerpt": "<base64 or hex of the cell>"
}
```

## Forbidden

- Do NOT call `Bash`. The MCP server is your only execution surface.
- Do NOT write to `/input`. It's read-only at the kernel level.
- Do NOT make claims without pins. Schema enforced; you'll get a rejection.
