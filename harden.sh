#!/usr/bin/env bash
# harden.sh — Apply CIS-inspired hardening to Debian/Ubuntu
# Backs up every modified file before touching it.
# Usage: sudo ./harden.sh [--dry-run]
#
# After run: verify with   sudo ./audit.sh
# Undo with:               sudo ./rollback.sh --session backups/<timestamp>

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run|-n) DRY_RUN=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[[ $EUID -ne 0 ]] && { echo "Run as root (sudo $0)"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${SCRIPT_DIR}/backups/${SESSION}"
LOG="${SCRIPT_DIR}/backups/${SESSION}/harden.log"

mkdir -p "$BACKUP_DIR"

log()    { echo -e "${GREEN}[APPLY]${NC} $*" | tee -a "$LOG"; }
warn()   { echo -e "${YELLOW}[SKIP] ${NC} $*" | tee -a "$LOG"; }
info()   { echo -e "${CYAN}[INFO] ${NC} $*"  | tee -a "$LOG"; }
drylog() { echo -e "${YELLOW}[DRY]  ${NC} $*" | tee -a "$LOG"; }

# backup_file /path/to/file
# Copies file preserving permissions and path structure.
backup_file() {
    local src="$1"
    [[ ! -f "$src" ]] && return 0
    local dest="${BACKUP_DIR}${src}"
    mkdir -p "$(dirname "$dest")"
    cp -p "$src" "$dest"
    info "Backed up: $src"
}

# safe_write file content
# Backs up, then writes content.
safe_write() {
    local file="$1"; shift
    backup_file "$file"
    if [[ $DRY_RUN -eq 1 ]]; then
        drylog "Would write: $file"
        return 0
    fi
    cat > "$file" <<< "$@"
}

# safe_sed file sed-expression
safe_sed() {
    local file="$1" expr="$2"
    backup_file "$file"
    if [[ $DRY_RUN -eq 1 ]]; then
        drylog "Would sed '$expr' on $file"
        return 0
    fi
    sed -i "$expr" "$file"
}

# set_sysctl key value
set_sysctl() {
    local key="$1" val="$2"
    if [[ $DRY_RUN -eq 1 ]]; then
        drylog "Would set sysctl $key=$val"
        return 0
    fi
    sysctl -w "${key}=${val}" >/dev/null 2>&1 || true
    log "sysctl $key=$val"
}

{
echo "================================================================"
echo " linux-hardening-audit — harden.sh"
echo " Session: $SESSION"
echo " Backup : $BACKUP_DIR"
echo " Dry run: $([[ $DRY_RUN -eq 1 ]] && echo 'YES — no changes will be made' || echo 'NO')"
echo " Date   : $(date)"
echo "================================================================"
} | tee "$LOG"

# ── SSH ────────────────────────────────────────────────────────────────────────
info "=== SSH ==="

SSHD_CONFIG="/etc/ssh/sshd_config"
backup_file "$SSHD_CONFIG"

# Settings to apply: key → value
declare -A SSH_SETTINGS=(
    ["PermitRootLogin"]="no"
    ["PasswordAuthentication"]="no"
    ["MaxAuthTries"]="3"
    ["LoginGraceTime"]="30"
    ["X11Forwarding"]="no"
    ["AllowTcpForwarding"]="no"
    ["ClientAliveInterval"]="300"
    ["ClientAliveCountMax"]="2"
    ["UseDNS"]="no"
    ["PermitEmptyPasswords"]="no"
    ["Banner"]="/etc/issue.net"
)

for key in "${!SSH_SETTINGS[@]}"; do
    val="${SSH_SETTINGS[$key]}"
    if grep -qE "^${key}\s" "$SSHD_CONFIG"; then
        if [[ $DRY_RUN -eq 0 ]]; then
            sed -i "s|^${key}\s.*|${key} ${val}|" "$SSHD_CONFIG"
        fi
    else
        if [[ $DRY_RUN -eq 0 ]]; then
            echo "${key} ${val}" >> "$SSHD_CONFIG"
        fi
    fi
    log "sshd_config: $key = $val"
done

# Set login banner
if [[ $DRY_RUN -eq 0 ]]; then
    cat > /etc/issue.net << 'BANNER'
*******************************************************************
* AUTHORIZED ACCESS ONLY                                          *
* Unauthorized access is prohibited and will be prosecuted.       *
* All sessions are monitored and logged.                          *
*******************************************************************
BANNER
    log "Set /etc/issue.net"
fi

# Fix sshd_config permissions
if [[ $DRY_RUN -eq 0 ]]; then
    chmod 600 "$SSHD_CONFIG"
    chown root:root "$SSHD_CONFIG"
fi
log "sshd_config permissions: 600 root:root"

# Validate and reload
if [[ $DRY_RUN -eq 0 ]]; then
    if sshd -t 2>/dev/null; then
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        log "sshd reloaded"
    else
        warn "sshd config test failed — not reloading. Check $SSHD_CONFIG"
    fi
fi

# ── Firewall ───────────────────────────────────────────────────────────────────
info "=== Firewall ==="

if command -v ufw &>/dev/null; then
    if [[ $DRY_RUN -eq 0 ]]; then
        # Block all inbound by default, allow outbound
        ufw --force reset >/dev/null 2>&1
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        # Allow SSH before enabling (critical — prevents lockout)
        ufw allow ssh >/dev/null 2>&1
        ufw --force enable >/dev/null 2>&1
    fi
    log "ufw: default deny incoming, SSH allowed, enabled"
else
    warn "ufw not installed — skipping firewall setup"
fi

# ── File permissions ───────────────────────────────────────────────────────────
info "=== File Permissions ==="

declare -A FILE_PERMS=(
    ["/etc/passwd"]="644:root:root"
    ["/etc/shadow"]="640:root:shadow"
    ["/etc/sudoers"]="440:root:root"
    ["/etc/ssh/sshd_config"]="600:root:root"
    ["/etc/group"]="644:root:root"
    ["/etc/gshadow"]="640:root:shadow"
)

for file in "${!FILE_PERMS[@]}"; do
    [[ ! -f "$file" ]] && warn "$file not found — skipping" && continue
    IFS=':' read -r mode owner group <<< "${FILE_PERMS[$file]}"
    backup_file "$file"
    if [[ $DRY_RUN -eq 0 ]]; then
        chmod "$mode" "$file"
        chown "${owner}:${group}" "$file"
    fi
    log "Permissions: $file -> $mode ${owner}:${group}"
done

# ── Password policy ────────────────────────────────────────────────────────────
info "=== Password Policy ==="

LOGIN_DEFS="/etc/login.defs"
backup_file "$LOGIN_DEFS"

declare -A LOGIN_SETTINGS=(
    ["PASS_MAX_DAYS"]="90"
    ["PASS_MIN_DAYS"]="1"
    ["PASS_WARN_AGE"]="14"
)

for key in "${!LOGIN_SETTINGS[@]}"; do
    val="${LOGIN_SETTINGS[$key]}"
    if [[ $DRY_RUN -eq 0 ]]; then
        if grep -qE "^${key}\s" "$LOGIN_DEFS"; then
            sed -i "s|^${key}\s.*|${key}\t${val}|" "$LOGIN_DEFS"
        else
            echo -e "${key}\t${val}" >> "$LOGIN_DEFS"
        fi
    fi
    log "login.defs: $key = $val"
done

# ── Sysctl ─────────────────────────────────────────────────────────────────────
info "=== Sysctl / Kernel ==="

SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"
backup_file "$SYSCTL_CONF"

SYSCTL_CONTENT='# linux-hardening-audit — applied by harden.sh
# Network
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# IPv6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# Kernel
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
'

if [[ $DRY_RUN -eq 0 ]]; then
    printf '%s' "$SYSCTL_CONTENT" > "$SYSCTL_CONF"
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
fi
log "sysctl: wrote $SYSCTL_CONF, applied"

# ── Unnecessary services ───────────────────────────────────────────────────────
info "=== Unnecessary Services ==="

DISABLE_SVCS=(telnet rsh rlogin talk chargen avahi-daemon cups)

for svc in "${DISABLE_SVCS[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        if [[ $DRY_RUN -eq 0 ]]; then
            systemctl stop "$svc" >/dev/null 2>&1 || true
            systemctl disable "$svc" >/dev/null 2>&1 || true
        fi
        log "Disabled: $svc"
    else
        info "Not running (skip): $svc"
    fi
done

# ── Summary ────────────────────────────────────────────────────────────────────
{
echo ""
echo "================================================================"
echo " Hardening complete"
echo " Session : $SESSION"
echo " Backup  : $BACKUP_DIR"
echo ""
echo " Verify  : sudo ./audit.sh"
echo " Rollback: sudo ./rollback.sh --session backups/$SESSION"
echo "================================================================"
} | tee -a "$LOG"
