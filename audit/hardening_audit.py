#!/usr/bin/env python3
"""Linux hardening audit (read-only).

Checks the effective SSH daemon settings, a set of kernel (sysctl) parameters
and permissions on a few sensitive files, then prints a PASS/FAIL report and a
score. The evaluation functions are pure, so they can be unit tested without
touching the real system.

Usage:
    python3 hardening_audit.py
    python3 hardening_audit.py --json
"""
import argparse
import glob
import json
import os
import stat
import sys
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional


@dataclass
class Check:
    id: str
    title: str
    status: str  # PASS, FAIL or SKIP
    detail: str


# id, title, sshd keyword (lowercase), predicate on the lowercase value, expectation text
SSH_RULES = [
    ("SSH-01", "Root login over SSH disabled", "permitrootlogin", lambda v: v == "no", "no"),
    ("SSH-02", "Password authentication disabled", "passwordauthentication", lambda v: v == "no", "no"),
    ("SSH-03", "Empty passwords not permitted", "permitemptypasswords", lambda v: v == "no", "no"),
    ("SSH-04", "X11 forwarding disabled", "x11forwarding", lambda v: v == "no", "no"),
    ("SSH-05", "MaxAuthTries is 4 or less", "maxauthtries", lambda v: v.isdigit() and int(v) <= 4, "<= 4"),
    ("SSH-06", "LoginGraceTime is 60s or less", "logingracetime", lambda v: v.isdigit() and 0 < int(v) <= 60, "<= 60"),
]

# sysctl key -> (id, title, acceptable values)
SYSCTL_RULES = {
    "net.ipv4.ip_forward": ("NET-01", "IP forwarding disabled", {"0"}),
    "net.ipv4.conf.all.accept_redirects": ("NET-02", "ICMP redirects not accepted", {"0"}),
    "net.ipv4.conf.all.send_redirects": ("NET-03", "ICMP redirects not sent", {"0"}),
    "net.ipv4.conf.all.accept_source_route": ("NET-04", "Source routing disabled", {"0"}),
    "net.ipv4.conf.all.rp_filter": ("NET-05", "Reverse path filtering enabled", {"1", "2"}),
    "net.ipv4.tcp_syncookies": ("NET-06", "TCP SYN cookies enabled", {"1"}),
    "net.ipv4.icmp_echo_ignore_broadcasts": ("NET-07", "Broadcast ICMP ignored", {"1"}),
    "kernel.randomize_va_space": ("KRN-01", "ASLR fully enabled", {"2"}),
    "fs.suid_dumpable": ("KRN-02", "No core dumps for SUID programs", {"0"}),
    "kernel.kptr_restrict": ("KRN-03", "Kernel pointers hidden", {"1", "2"}),
    "kernel.dmesg_restrict": ("KRN-04", "dmesg restricted to root", {"1"}),
}

# path -> (id, most permissive mode allowed)
MODE_RULES = {
    "/etc/passwd": ("FIL-01", 0o644),
    "/etc/shadow": ("FIL-02", 0o640),
    "/etc/ssh/sshd_config": ("FIL-03", 0o600),
}


def parse_sshd(text: str) -> Dict[str, str]:
    """Parse one sshd config file. First occurrence of a keyword wins (as in sshd).
    Parsing stops at the first Match block because later settings are conditional."""
    cfg: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        if key == "match":
            break
        value = parts[1].strip().lower() if len(parts) > 1 else ""
        cfg.setdefault(key, value)
    return cfg


def merge_configs(configs: List[Dict[str, str]]) -> Dict[str, str]:
    """Merge parsed files in the order sshd reads them; earlier files win."""
    merged: Dict[str, str] = {}
    for cfg in configs:
        for k, v in cfg.items():
            merged.setdefault(k, v)
    return merged


def check_ssh(cfg: Dict[str, str]) -> List[Check]:
    results = []
    for cid, title, key, ok, expected in SSH_RULES:
        value = cfg.get(key)
        if value is None:
            results.append(Check(cid, title, "FAIL", f"{key} not set explicitly (want {expected})"))
        elif ok(value):
            results.append(Check(cid, title, "PASS", f"{key} = {value}"))
        else:
            results.append(Check(cid, title, "FAIL", f"{key} = {value} (want {expected})"))
    return results


def check_sysctl(values: Dict[str, Optional[str]]) -> List[Check]:
    results = []
    for key, (cid, title, allowed) in SYSCTL_RULES.items():
        value = values.get(key)
        if value is None:
            results.append(Check(cid, title, "SKIP", f"{key} not readable on this system"))
        elif value in allowed:
            results.append(Check(cid, title, "PASS", f"{key} = {value}"))
        else:
            results.append(Check(cid, title, "FAIL", f"{key} = {value} (want {'/'.join(sorted(allowed))})"))
    return results


def check_modes(modes: Dict[str, Optional[int]]) -> List[Check]:
    results = []
    for path, (cid, max_mode) in MODE_RULES.items():
        mode = modes.get(path)
        title = f"{path} permissions {oct(max_mode)[2:]} or stricter"
        if mode is None:
            results.append(Check(cid, title, "SKIP", f"{path} not found"))
        elif mode & ~max_mode:
            results.append(Check(cid, title, "FAIL", f"mode is {oct(mode)[2:]}"))
        else:
            results.append(Check(cid, title, "PASS", f"mode is {oct(mode)[2:]}"))
    return results


def score(checks: List[Check]) -> int:
    scored = [c for c in checks if c.status in ("PASS", "FAIL")]
    if not scored:
        return 0
    return round(100 * sum(c.status == "PASS" for c in scored) / len(scored))


# --- system readers (the only part that touches the real machine) ---

def read_sshd_configs() -> List[Dict[str, str]]:
    paths = sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")) + ["/etc/ssh/sshd_config"]
    configs = []
    for p in paths:
        try:
            with open(p, errors="replace") as fh:
                configs.append(parse_sshd(fh.read()))
        except OSError:
            continue
    return configs


def read_sysctl() -> Dict[str, Optional[str]]:
    values: Dict[str, Optional[str]] = {}
    for key in SYSCTL_RULES:
        try:
            with open("/proc/sys/" + key.replace(".", "/")) as fh:
                values[key] = fh.read().strip()
        except OSError:
            values[key] = None
    return values


def read_modes() -> Dict[str, Optional[int]]:
    modes: Dict[str, Optional[int]] = {}
    for path in MODE_RULES:
        try:
            modes[path] = stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            modes[path] = None
    return modes


def main() -> int:
    p = argparse.ArgumentParser(description="Read-only Linux hardening audit")
    p.add_argument("--json", action="store_true", help="output JSON")
    args = p.parse_args()

    checks = (check_ssh(merge_configs(read_sshd_configs()))
              + check_sysctl(read_sysctl())
              + check_modes(read_modes()))

    if args.json:
        print(json.dumps({"score": score(checks), "checks": [asdict(c) for c in checks]}, indent=2))
    else:
        for c in checks:
            print(f"[{c.status:4}] {c.id}  {c.title}  ({c.detail})")
        print(f"\nHardening score: {score(checks)}%")
    return 1 if any(c.status == "FAIL" for c in checks) else 0


if __name__ == "__main__":
    sys.exit(main())
