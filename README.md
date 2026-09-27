# linux-hardening-audit

CIS-inspired security audit and one-command hardening for Debian 11/12 and Ubuntu 20.04/22.04.

Solves the real problem: a freshly provisioned Debian server fails ~14 of 28 security controls by default. This tool audits, fixes, and can fully roll back — without relying on Ansible or any extra toolchain.

## Result

| Metric | Before | After |
|---|---|---|
| Controls passed | 9 / 28 (32%) | 25 / 28 (89%) |
| FAIL count | 14 | 0 |
| Time to harden | — | < 60 s |

Full output: [`reports/before-sample.txt`](reports/before-sample.txt) · [`reports/after-sample.txt`](reports/after-sample.txt)

## What it covers

28 controls across 7 categories — see [`checklist.md`](checklist.md) for the full list with CIS Benchmark references.

| Category | Controls | Tools touched |
|---|---|---|
| SSH | 7 | `/etc/ssh/sshd_config` |
| Firewall | 2 | `ufw`, `iptables` |
| File permissions | 6 | `chmod`, `chown` |
| Password policy | 3 | `/etc/login.defs` |
| Sysctl / Kernel | 7 | `/etc/sysctl.d/99-hardening.conf` |
| Unnecessary services | 5 | `systemctl` |
| Users | 3 | `/etc/shadow`, `/etc/sudoers` |

## Requirements

- Debian 11/12 or Ubuntu 20.04/22.04
- `bash` ≥ 4, `ufw`, `iptables`, `systemctl`
- Root access (`sudo`)

## Quick start

```bash
git clone https://github.com/grainframe/linux-hardening-audit
cd linux-hardening-audit
chmod +x audit.sh harden.sh rollback.sh

# 1. Audit — see what's failing
sudo ./audit.sh --output reports/before.txt

# 2. Harden (backs up every file before modifying)
sudo ./harden.sh

# 3. Audit again
sudo ./audit.sh --output reports/after.txt

# 4. Roll back everything if needed
sudo ./rollback.sh --list
sudo ./rollback.sh --session backups/20240923_140945
```

`--dry-run` flag shows what `harden.sh` would do without making any changes:

```bash
sudo ./harden.sh --dry-run
```

## Rollback safety

`harden.sh` creates a timestamped backup session under `backups/<timestamp>/` before touching any file. The original path is preserved inside the session directory.

```
backups/
└── 20240923_140945/
    ├── harden.log
    ├── etc/
    │   ├── ssh/
    │   │   └── sshd_config
    │   ├── login.defs
    │   └── sudoers
    └── etc/sysctl.d/
        └── 99-hardening.conf
```

`rollback.sh --session backups/<timestamp>` restores all files from that session and reloads the relevant daemons (`sshd`, `sysctl`).

No file is modified without a backup. No backup is deleted by this tool.

## Repository layout

```
linux-hardening-audit/
├── audit.sh          # Audit only — read-only, safe to run any time
├── harden.sh         # Apply fixes (backs up first)
├── rollback.sh       # Restore from any backup session
├── checklist.md      # All 28 controls with CIS references
├── reports/
│   ├── before-sample.txt
│   └── after-sample.txt
└── backups/          # Created at runtime, gitignored
```

## Tested on

| OS | Version |
|---|---|
| Debian | 11 (bullseye), 12 (bookworm) |
| Ubuntu | 20.04 LTS, 22.04 LTS |
