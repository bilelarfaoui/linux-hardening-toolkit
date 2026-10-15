#!/usr/bin/env bash
# apply_hardening.sh - apply a baseline of SSH, kernel and file-permission hardening.
#
#   ./scripts/apply_hardening.sh            # dry run: only prints what would change
#   sudo ./scripts/apply_hardening.sh --apply
#
# Keep a second SSH session open while applying, in case you get locked out.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
run()  { if (( APPLY )); then "$@"; else log "DRY-RUN: $*"; fi; }

if (( APPLY )) && [[ $EUID -ne 0 ]]; then
    echo "Run as root (sudo) when using --apply" >&2
    exit 1
fi

BACKUP_DIR="/var/backups/hardening-$(date +%Y%m%d-%H%M%S)"

backup() {
    log "Backing up config to $BACKUP_DIR"
    run mkdir -p "$BACKUP_DIR"
    [[ -d /etc/ssh ]] && run cp -a /etc/ssh "$BACKUP_DIR/ssh"
    [[ -d /etc/sysctl.d ]] && run cp -a /etc/sysctl.d "$BACKUP_DIR/sysctl.d"
    return 0
}

harden_ssh() {
    local sshd_conf=/etc/ssh/sshd_config
    local dropin=/etc/ssh/sshd_config.d/00-hardening.conf

    if [[ ! -f $sshd_conf ]]; then
        log "No sshd_config found, skipping SSH hardening"
        return 0
    fi
    if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/' "$sshd_conf"; then
        warn "sshd_config has no Include for sshd_config.d; skipping SSH step"
        return 0
    fi

    # Never disable password login for someone with no key to fall back on.
    local user="${SUDO_USER:-$(id -un)}" home
    home="$(getent passwd "$user" | cut -d: -f6)"
    if [[ ! -s "$home/.ssh/authorized_keys" ]]; then
        warn "$user has no authorized_keys; skipping SSH step to avoid a lockout"
        return 0
    fi

    log "Installing SSH drop-in $dropin"
    run mkdir -p /etc/ssh/sshd_config.d
    run install -m 0644 -o root -g root "$REPO_DIR/configs/00-hardening.conf" "$dropin"

    if (( APPLY )); then
        if ! sshd -t; then
            warn "sshd config test failed, rolling back"
            rm -f "$dropin"
            return 1
        fi
        systemctl reload ssh 2>/dev/null || systemctl reload sshd
        log "sshd reloaded"
    fi
}

harden_kernel() {
    log "Installing sysctl settings"
    run install -m 0644 -o root -g root "$REPO_DIR/configs/99-hardening-sysctl.conf" \
        /etc/sysctl.d/99-hardening.conf
    if (( APPLY )); then sysctl --system >/dev/null; fi
}

harden_permissions() {
    log "Tightening permissions (only ever removes access)"
    [[ -f /etc/passwd ]]            && run chmod go-w   /etc/passwd
    [[ -f /etc/shadow ]]            && run chmod g-wx,o-rwx /etc/shadow
    [[ -f /etc/ssh/sshd_config ]]   && run chmod go-rwx /etc/ssh/sshd_config
    return 0
}

backup
harden_ssh
harden_kernel
harden_permissions

log "Done. Verify with: python3 $REPO_DIR/audit/hardening_audit.py"
