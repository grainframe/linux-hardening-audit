#!/usr/bin/env bash
# audit.sh — CIS-inspired security audit for Debian/Ubuntu
# Usage: sudo ./audit.sh [--output /path/to/report.txt]
# Requires: bash >= 4, root privileges

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

REPORT="${REPORT:-/tmp/audit_$(hostname)_$(date +%Y%m%d_%H%M%S).txt}"
PASS=0; FAIL=0; WARN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output|-o) REPORT="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[[ $EUID -ne 0 ]] && { echo "Run as root (sudo $0)"; exit 1; }

_pass() { echo -e "${GREEN}[PASS]${NC} [$1] $2" | tee -a "$REPORT"; PASS=$((PASS+1)); }
_fail() { echo -e "${RED}[FAIL]${NC} [$1] $2" | tee -a "$REPORT"; FAIL=$((FAIL+1)); }
_warn() { echo -e "${YELLOW}[WARN]${NC} [$1] $2" | tee -a "$REPORT"; WARN=$((WARN+1)); }
_head() { echo -e "\n${CYAN}${BOLD}--- $1 ---${NC}" | tee -a "$REPORT"; }

# run_check LEVEL id "description" bash-expression
run_check() {
    local level="$1" id="$2" desc="$3" expr="$4"
    if bash -c "$expr" >/dev/null 2>&1; then
        _pass "$id" "$desc"
    elif [[ "$level" == "FAIL" ]]; then
        _fail "$id" "$desc"
    else
        _warn "$id" "$desc"
    fi
}

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONF_DIR="/etc/ssh/sshd_config.d"
LOGIN_DEFS="/etc/login.defs"

# Helper: get effective sshd value (config + includes)
sshd_val() {
    local key="$1"
    # Check includes first (they override), then main config
    if [[ -d "$SSHD_CONF_DIR" ]]; then
        grep -rh "^${key}" "$SSHD_CONF_DIR"/*.conf 2>/dev/null | tail -1 | awk '{print $2}' | tr '[:upper:]' '[:lower:]'
    fi
    grep -h "^${key}" "$SSHD_CONFIG" 2>/dev/null | tail -1 | awk '{print $2}' | tr '[:upper:]' '[:lower:]'
}

{
echo "================================================================"
echo " linux-hardening-audit"
echo " Host   : $(hostname)"
echo " Date   : $(date)"
echo " OS     : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo "Unknown")"
echo " Kernel : $(uname -r)"
echo "================================================================"
} | tee "$REPORT"

# ── SSH ────────────────────────────────────────────────────────────────────────
_head "SSH"

run_check FAIL SSH-01 "PermitRootLogin is no or prohibit-password" \
    "grep -qiE '^PermitRootLogin[[:space:]]+(no|prohibit-password)' \"$SSHD_CONFIG\" || \
     grep -rqiE '^PermitRootLogin[[:space:]]+(no|prohibit-password)' \"$SSHD_CONF_DIR\"/ 2>/dev/null"

run_check FAIL SSH-02 "PasswordAuthentication no" \
    "grep -qiE '^PasswordAuthentication[[:space:]]+no' \"$SSHD_CONFIG\" || \
     grep -rqiE '^PasswordAuthentication[[:space:]]+no' \"$SSHD_CONF_DIR\"/ 2>/dev/null"

run_check FAIL SSH-03 "MaxAuthTries <= 3" \
    "val=\$(grep -h '^MaxAuthTries' \"$SSHD_CONFIG\" 2>/dev/null | awk '{print \$2}'); [[ -n \"\$val\" ]] && [[ \$val -le 3 ]]"

run_check FAIL SSH-04 "LoginGraceTime <= 60" \
    "val=\$(grep -h '^LoginGraceTime' \"$SSHD_CONFIG\" 2>/dev/null | awk '{print \$2}'); [[ -n \"\$val\" ]] && [[ \$val -le 60 ]]"

run_check FAIL SSH-05 "X11Forwarding no" \
    "grep -qiE '^X11Forwarding[[:space:]]+no' \"$SSHD_CONFIG\" || \
     grep -rqiE '^X11Forwarding[[:space:]]+no' \"$SSHD_CONF_DIR\"/ 2>/dev/null"

run_check WARN SSH-06 "AllowUsers or AllowGroups defined" \
    "grep -qiE '^(AllowUsers|AllowGroups)' \"$SSHD_CONFIG\" || \
     grep -rqiE '^(AllowUsers|AllowGroups)' \"$SSHD_CONF_DIR\"/ 2>/dev/null"

run_check WARN SSH-07 "Protocol not explicitly set to 1" \
    "! grep -qiE '^Protocol[[:space:]]+1$' \"$SSHD_CONFIG\""

# ── Firewall ───────────────────────────────────────────────────────────────────
_head "Firewall"

run_check FAIL FW-01 "ufw active" \
    "ufw status 2>/dev/null | grep -q 'Status: active'"

run_check WARN FW-02 "iptables INPUT chain has explicit rules" \
    "iptables -L INPUT -n 2>/dev/null | grep -cqv '^Chain\|^target\|^$'"

# ── File permissions ───────────────────────────────────────────────────────────
_head "File Permissions"

run_check FAIL PERM-01 "/etc/passwd is 644" \
    "[[ \$(stat -c '%a' /etc/passwd) == '644' ]]"

run_check FAIL PERM-02 "/etc/shadow is 640 or stricter" \
    "mode=\$(stat -c '%a' /etc/shadow); [[ \$mode == '640' || \$mode == '600' || \$mode == '000' ]]"

run_check FAIL PERM-03 "/etc/sudoers is 440" \
    "[[ \$(stat -c '%a' /etc/sudoers) == '440' ]]"

run_check FAIL PERM-04 "/etc/ssh/sshd_config is 600" \
    "[[ \$(stat -c '%a' /etc/ssh/sshd_config) == '600' ]]"

run_check WARN PERM-05 "No world-writable files in /etc" \
    "! find /etc -maxdepth 2 -perm -002 -type f 2>/dev/null | grep -q ."

run_check WARN PERM-06 "No SUID files outside standard paths" \
    "count=\$(find / -xdev -perm /4000 2>/dev/null | grep -vE '^/(bin|sbin|usr/bin|usr/sbin|usr/lib)/' | wc -l); [[ \$count -eq 0 ]]"

# ── Password policy ────────────────────────────────────────────────────────────
_head "Password Policy"

run_check FAIL PASS-01 "PASS_MAX_DAYS <= 90" \
    "val=\$(awk '/^PASS_MAX_DAYS/ {print \$2}' \"$LOGIN_DEFS\"); [[ -n \"\$val\" ]] && [[ \$val -le 90 ]]"

run_check FAIL PASS-02 "PASS_MIN_DAYS >= 1" \
    "val=\$(awk '/^PASS_MIN_DAYS/ {print \$2}' \"$LOGIN_DEFS\"); [[ -n \"\$val\" ]] && [[ \$val -ge 1 ]]"

run_check FAIL PASS-03 "PASS_WARN_AGE >= 7" \
    "val=\$(awk '/^PASS_WARN_AGE/ {print \$2}' \"$LOGIN_DEFS\"); [[ -n \"\$val\" ]] && [[ \$val -ge 7 ]]"

# ── Sysctl / Kernel ────────────────────────────────────────────────────────────
_head "Sysctl / Kernel"

run_check FAIL SYSCTL-01 "IPv4 forwarding disabled" \
    "[[ \$(sysctl -n net.ipv4.ip_forward 2>/dev/null) == '0' ]]"

run_check FAIL SYSCTL-02 "ICMP redirects not accepted (all)" \
    "[[ \$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null) == '0' ]]"

run_check FAIL SYSCTL-03 "Source routing disabled" \
    "[[ \$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null) == '0' ]]"

run_check FAIL SYSCTL-04 "SYN flood protection on" \
    "[[ \$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null) == '1' ]]"

run_check WARN SYSCTL-05 "Martian packets logged" \
    "[[ \$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null) == '1' ]]"

run_check WARN SYSCTL-06 "ASLR fully enabled (= 2)" \
    "[[ \$(sysctl -n kernel.randomize_va_space 2>/dev/null) == '2' ]]"

run_check WARN SYSCTL-07 "Broadcast ICMP disabled" \
    "[[ \$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null) == '1' ]]"

# ── Unnecessary services ───────────────────────────────────────────────────────
_head "Unnecessary Services"

for svc in telnet rsh rlogin talk chargen; do
    run_check WARN "SVC-${svc}" "Service '${svc}' not running" \
        "! systemctl is-active --quiet \"$svc\" 2>/dev/null && \
         ! dpkg -l \"$svc\" 2>/dev/null | grep -q '^ii'"
done

# ── Users ──────────────────────────────────────────────────────────────────────
_head "Users"

run_check FAIL USR-01 "No accounts with empty passwords" \
    "! awk -F: '(\$2 == \"\") {found=1} END {exit !found}' /etc/shadow 2>/dev/null"

run_check FAIL USR-02 "Only root has UID 0" \
    "[[ \$(awk -F: '(\$3==0){print \$1}' /etc/passwd | grep -vc '^root$') -eq 0 ]]"

run_check WARN USR-03 "No users with UID >= 1000 in /etc/sudoers with NOPASSWD" \
    "! grep -v '^#' /etc/sudoers 2>/dev/null | grep -q 'NOPASSWD'"

# ── Summary ────────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + WARN))
{
echo ""
echo "================================================================"
echo " Summary"
echo " Total  : $TOTAL"
echo " PASS   : $PASS"
echo " FAIL   : $FAIL"
echo " WARN   : $WARN"
echo " Score  : $PASS / $TOTAL  ($(( PASS * 100 / TOTAL ))%)"
echo "================================================================"
} | tee -a "$REPORT"

echo -e "\nReport saved: ${BOLD}${REPORT}${NC}"

# Exit 1 if any FAIL
[[ $FAIL -gt 0 ]] && exit 1 || exit 0
