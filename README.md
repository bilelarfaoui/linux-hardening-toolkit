# Linux Hardening Toolkit

A small toolkit I put together to harden Linux servers and to measure the result. It has three parts:

- **Audit** (`audit/hardening_audit.py`): a read-only Python script that checks SSH settings, kernel parameters and file permissions, then prints PASS/FAIL per control and an overall score.
- **Apply** (`scripts/apply_hardening.sh`): a Bash script that installs the baseline. It is a dry run by default.
- **Ansible** (`ansible/playbook.yml`): the same baseline as a playbook for managing more than one host.

The controls and the reasoning behind each one are in [docs/CHECKLIST.md](docs/CHECKLIST.md).

## Quick start

```bash
# 1. See where a machine stands today
python3 audit/hardening_audit.py

# 2. Preview the changes (nothing is modified)
./scripts/apply_hardening.sh

# 3. Apply them (keep a second SSH session open)
sudo ./scripts/apply_hardening.sh --apply

# 4. Re-run the audit to confirm
python3 audit/hardening_audit.py
```

The audit exits with code `1` if any check fails, so it also works as a CI or cron gate. Add `--json` for machine-readable output.

## Safety features

- **Dry run by default**: nothing changes unless you pass `--apply`.
- **Backups**: `/etc/ssh` and `/etc/sysctl.d` are copied to `/var/backups/hardening-<timestamp>` first.
- **Lockout protection**: the SSH step is skipped if your user has no `authorized_keys`, because it disables password login.
- **Validated and reversible**: `sshd -t` runs before the reload, and the drop-in is removed if validation fails.
- **Permissions only tighten**: it uses `chmod` removals (`go-w`, `o-rwx`) so it can never loosen a file.
- **Drop-in ordering**: the SSH file is named `00-hardening.conf` because sshd uses the first value it finds, so it must be read before files such as `50-cloud-init.conf`.

## Things to know

- `net.ipv4.ip_forward = 0` breaks Docker, Kubernetes and VPN gateways. Remove that line from `configs/99-hardening-sysctl.conf` on those hosts.
- The audit treats an SSH setting that is not set explicitly as a failure, even where the OpenSSH default would be safe. I prefer hardening to be visible in config.
- This is a baseline, not a full CIS benchmark implementation. See "Not covered yet" in the checklist.

## Tests

```bash
cd audit
python3 -m unittest -v
```

The audit logic is pure functions over parsed data, so the tests run without root or a real SSH daemon.

## Status

The audit logic is unit tested. The apply script and Ansible playbook should be tried on a disposable VM before any real server; I have not yet validated them across distributions.

## Roadmap

- Firewall (nftables/ufw) baseline
- auditd rules and log forwarding
- PAM password policy and account lockout
- Unattended security updates
- Map checks to CIS Benchmark control numbers

## Disclaimer

Only run this on systems you own or are authorized to administer. Misconfigured SSH hardening can lock you out of a machine.
