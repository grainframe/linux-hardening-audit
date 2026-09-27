# Hardening Checklist

All controls checked by `audit.sh` and applied by `harden.sh`.  
References: CIS Benchmark for Debian Linux 11/Ubuntu 22.04.

## SSH (7 controls)

| ID | Control | Level | CIS ref |
|----|---------|-------|---------|
| SSH-01 | `PermitRootLogin no` or `prohibit-password` | FAIL | 5.2.8 |
| SSH-02 | `PasswordAuthentication no` | FAIL | 5.2.11 |
| SSH-03 | `MaxAuthTries` ≤ 3 | FAIL | 5.2.7 |
| SSH-04 | `LoginGraceTime` ≤ 60 s | FAIL | 5.2.16 |
| SSH-05 | `X11Forwarding no` | FAIL | 5.2.6 |
| SSH-06 | `AllowUsers` or `AllowGroups` defined | WARN | 5.2.17 |
| SSH-07 | Protocol version 1 not forced | WARN | 5.2.1 |

> **Note:** On Ubuntu 22.04+ some settings may live in `/etc/ssh/sshd_config.d/`.  
> `audit.sh` checks both the main config and the include directory.

## Firewall (2 controls)

| ID | Control | Level |
|----|---------|-------|
| FW-01 | `ufw` active | FAIL |
| FW-02 | `iptables` INPUT chain has explicit rules | WARN |

## File Permissions (6 controls)

| ID | File | Expected mode | Level |
|----|------|--------------|-------|
| PERM-01 | `/etc/passwd` | 644 | FAIL |
| PERM-02 | `/etc/shadow` | 640 or stricter | FAIL |
| PERM-03 | `/etc/sudoers` | 440 | FAIL |
| PERM-04 | `/etc/ssh/sshd_config` | 600 | FAIL |
| PERM-05 | No world-writable files in `/etc` | — | WARN |
| PERM-06 | No unusual SUID binaries | — | WARN |

## Password Policy (3 controls)

| ID | `/etc/login.defs` setting | Required | Level |
|----|--------------------------|----------|-------|
| PASS-01 | `PASS_MAX_DAYS` | ≤ 90 | FAIL |
| PASS-02 | `PASS_MIN_DAYS` | ≥ 1 | FAIL |
| PASS-03 | `PASS_WARN_AGE` | ≥ 7 | FAIL |

> Password aging only applies to new accounts after the change.  
> Apply to existing accounts with: `chage -M 90 -m 1 -W 14 <username>`

## Sysctl / Kernel (7 controls)

| ID | Parameter | Required value | Level |
|----|-----------|---------------|-------|
| SYSCTL-01 | `net.ipv4.ip_forward` | 0 | FAIL |
| SYSCTL-02 | `net.ipv4.conf.all.accept_redirects` | 0 | FAIL |
| SYSCTL-03 | `net.ipv4.conf.all.accept_source_route` | 0 | FAIL |
| SYSCTL-04 | `net.ipv4.tcp_syncookies` | 1 | FAIL |
| SYSCTL-05 | `net.ipv4.conf.all.log_martians` | 1 | WARN |
| SYSCTL-06 | `kernel.randomize_va_space` | 2 | WARN |
| SYSCTL-07 | `net.ipv4.icmp_echo_ignore_broadcasts` | 1 | WARN |

Full list applied by `harden.sh` written to `/etc/sysctl.d/99-hardening.conf`.

## Unnecessary Services (5 controls)

| ID | Service | Level |
|----|---------|-------|
| SVC-telnet | telnet not running/installed | WARN |
| SVC-rsh | rsh not running/installed | WARN |
| SVC-rlogin | rlogin not running/installed | WARN |
| SVC-talk | talk not running/installed | WARN |
| SVC-chargen | chargen not running/installed | WARN |

## Users (3 controls)

| ID | Control | Level |
|----|---------|-------|
| USR-01 | No accounts with empty passwords in `/etc/shadow` | FAIL |
| USR-02 | Only `root` has UID 0 | FAIL |
| USR-03 | No `NOPASSWD` in `/etc/sudoers` for UID ≥ 1000 | WARN |

---

## FAIL vs WARN

- **FAIL** — direct security risk; `audit.sh` exits 1 if any FAIL present
- **WARN** — best-practice deviation; does not affect exit code
