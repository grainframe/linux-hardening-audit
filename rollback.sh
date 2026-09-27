#!/usr/bin/env bash
# rollback.sh — Restore files backed up by harden.sh
# Usage: sudo ./rollback.sh [--session backups/<timestamp>] [--list]

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION=""
LIST_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --session|-s) SESSION="$2"; shift 2 ;;
        --list|-l)    LIST_ONLY=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[[ $EUID -ne 0 ]] && { echo "Run as root (sudo $0)"; exit 1; }

BACKUP_ROOT="${SCRIPT_DIR}/backups"

# ── List available sessions ────────────────────────────────────────────────────
list_sessions() {
    echo -e "${CYAN}${BOLD}Available backup sessions:${NC}"
    if [[ ! -d "$BACKUP_ROOT" ]] || [[ -z "$(ls -A "$BACKUP_ROOT" 2>/dev/null)" ]]; then
        echo "  (none)"
        return
    fi
    for d in "$BACKUP_ROOT"/*/; do
        [[ -d "$d" ]] || continue
        name="$(basename "$d")"
        count="$(find "$d" -type f ! -name 'harden.log' | wc -l)"
        log_exists="$([[ -f "$d/harden.log" ]] && echo "log present" || echo "no log")"
        echo "  $name  ($count files backed up, $log_exists)"
    done
}

if [[ $LIST_ONLY -eq 1 ]]; then
    list_sessions
    exit 0
fi

if [[ -z "$SESSION" ]]; then
    list_sessions
    echo ""
    read -r -p "Enter session name to restore (or Ctrl-C to cancel): " SESSION
fi

SESSION_DIR="${SCRIPT_DIR}/${SESSION}"
[[ "$SESSION_DIR" != "${BACKUP_ROOT}/"* ]] && SESSION_DIR="${BACKUP_ROOT}/${SESSION}"

if [[ ! -d "$SESSION_DIR" ]]; then
    echo -e "${RED}Session not found: $SESSION_DIR${NC}"
    exit 1
fi

echo -e "${CYAN}${BOLD}Restoring from: $SESSION_DIR${NC}"
echo ""

RESTORED=0
SKIPPED=0
ERRORS=0

while IFS= read -r -d '' backup_file; do
    # Strip session dir prefix to get original path
    relative="${backup_file#$SESSION_DIR}"
    # Skip harden.log
    [[ "$relative" == "/harden.log" ]] && continue

    original="$relative"

    if [[ -f "$original" ]]; then
        cp -p "$backup_file" "$original" && {
            echo -e "${GREEN}[RESTORED]${NC} $original"
            RESTORED=$((RESTORED+1))
        } || {
            echo -e "${RED}[ERROR]   ${NC} Failed to restore $original"
            ERRORS=$((ERRORS+1))
        }
    else
        # File didn't exist before hardening — remove it
        echo -e "${YELLOW}[REMOVE]  ${NC} $original (did not exist before hardening)"
        rm -f "$original" && RESTORED=$((RESTORED+1)) || ERRORS=$((ERRORS+1))
    fi
done < <(find "$SESSION_DIR" -type f -print0)

# Reload sshd if its config was restored
if find "$SESSION_DIR" -path "*/ssh/sshd_config" | grep -q .; then
    sshd -t 2>/dev/null && {
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        echo -e "${GREEN}[INFO]    ${NC} sshd reloaded"
    } || echo -e "${YELLOW}[WARN]    ${NC} sshd config test failed — check manually"
fi

# Reload sysctl if sysctl config was restored / removed
if find "$SESSION_DIR" -path "*/sysctl.d/99-hardening.conf" | grep -q .; then
    sysctl --system >/dev/null 2>&1 || true
    echo -e "${GREEN}[INFO]    ${NC} sysctl reloaded"
fi

echo ""
echo "================================================================"
echo " Rollback complete"
echo " Restored : $RESTORED"
echo " Skipped  : $SKIPPED"
echo " Errors   : $ERRORS"
echo " Verify   : sudo ./audit.sh"
echo "================================================================"

[[ $ERRORS -gt 0 ]] && exit 1 || exit 0
