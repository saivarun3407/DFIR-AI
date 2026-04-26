---
name: linux-triage
description: Linux DFIR artifact triage. Use when evidence is Linux (ext4 image, systemd journal, audit logs, shell history, persistence vectors, container artifacts). Encodes FOR577 baseline.
---

# Linux Triage

## Investigation Order

### 1. Authentication / Logon
- `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS)
- systemd journal: `journalctl -u sshd --since=...`
- `last`, `lastb`, `wtmp`, `btmp`, `utmp`
- `~/.ssh/authorized_keys` — added/changed = persistence vector
- `/etc/passwd`, `/etc/shadow`, `/etc/group` — UID 0 != root scrutiny

### 2. Command Execution
- Shell history: `~/.bash_history`, `~/.zsh_history`, `~/.python_history`, `~/.lesshst`, `~/.viminfo`
- `auditd` log: `/var/log/audit/audit.log` — execve syscalls
- systemd journal `_COMM=` filter
- sudoers: `/etc/sudoers`, `/etc/sudoers.d/*`

### 3. Persistence Vectors (high signal for IR)
- systemd units: `/etc/systemd/system/*`, `/lib/systemd/system/*`, `~/.config/systemd/user/*`
- cron: `/etc/crontab`, `/etc/cron.{hourly,daily,weekly,monthly}`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/*`
- init scripts: `/etc/init.d/*`, `/etc/rc*.d/*`, `/etc/rc.local`
- shell rc: `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `/etc/profile.d/*`
- LD_PRELOAD / `/etc/ld.so.preload` (rootkit indicator)
- kernel modules: `/lib/modules/$(uname -r)/`, `lsmod` snapshot
- xdg autostart: `~/.config/autostart/*.desktop`

### 4. Network
- `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`
- iptables / nftables rules state
- conntrack: `/proc/net/nf_conntrack`
- listening sockets: `ss -tulpn` snapshot
- NetworkManager: `/etc/NetworkManager/system-connections/`

### 5. Containers (if Docker/Podman host)
- docker.sock activity in audit log
- container layers: `/var/lib/docker/overlay2/`
- runc state: `/run/runc/`
- image manifests: `/var/lib/docker/image/`
- container logs: `/var/lib/docker/containers/<id>/<id>-json.log`

### 6. Memory (if dump available)
Volatility 3 `linux.*` plugins: `pslist`, `psaux`, `bash`, `pstree`, `lsof`, `psscan`, `malfind` (limited), `sockstat`, `iomem`

## MCP Tools

- `mcp__protocol_sift__linux_journal_query(unit, since, until, predicate)` → journal entries
- `mcp__protocol_sift__linux_audit_query(syscall, time_range)` → audit events
- `mcp__protocol_sift__linux_history_parse(path)` → history entries with line numbers
- `mcp__protocol_sift__linux_systemd_units(image_path)` → enumerated units
- `mcp__protocol_sift__linux_cron_parse(image_path)` → all cron entries

## Pin Format

```json
{
  "artifact": "/var/log/audit/audit.log",
  "tool": "linux_audit_query",
  "line": 4823,
  "msg_id": "audit(1714...)",
  "raw_excerpt": "type=EXECVE msg=audit(...) argc=3 a0=\"sh\" a1=\"-c\" a2=\"curl ...\""
}
```

## Cross-Confirmation Rules

- Process execution: bash_history + audit execve + journal `_COMM=` = `confirmed`
- Persistence: systemd unit + recently modified rc + audit chmod/chown = `confirmed`
- Network exfil: conntrack + listening socket + journal = `confirmed`. Conntrack alone = `inferred`.
