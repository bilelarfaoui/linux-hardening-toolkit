# Control checklist

Every control the audit script checks, and why it matters.

| ID | Control | Why it matters |
|----|---------|----------------|
| SSH-01 | `PermitRootLogin no` | Forces attackers to guess a username as well as a password, and gives you per-user audit trails via sudo. |
| SSH-02 | `PasswordAuthentication no` | Removes password brute force as an attack path; keys only. |
| SSH-03 | `PermitEmptyPasswords no` | Blocks accounts with blank passwords from logging in. |
| SSH-04 | `X11Forwarding no` | Reduces attack surface on servers that never need GUI forwarding. |
| SSH-05 | `MaxAuthTries <= 4` | Limits guesses per connection and makes brute force noisier. |
| SSH-06 | `LoginGraceTime <= 60` | Shortens the window for unauthenticated connections to hold resources. |
| NET-01 | `net.ipv4.ip_forward = 0` | A normal host should not route traffic. Breaks Docker/Kubernetes hosts, so skip there. |
| NET-02 | `accept_redirects = 0` | Prevents routing-table manipulation via forged ICMP redirects. |
| NET-03 | `send_redirects = 0` | A non-router should not send redirects. |
| NET-04 | `accept_source_route = 0` | Source-routed packets let senders choose the path, which enables spoofing. |
| NET-05 | `rp_filter = 1` | Drops packets with spoofed source addresses. |
| NET-06 | `tcp_syncookies = 1` | Mitigates SYN flood denial of service. |
| NET-07 | `icmp_echo_ignore_broadcasts = 1` | Stops the host being used in smurf-style amplification. |
| KRN-01 | `randomize_va_space = 2` | Full ASLR makes memory-corruption exploits harder. |
| KRN-02 | `fs.suid_dumpable = 0` | Prevents core dumps of privileged programs leaking secrets. |
| KRN-03 | `kernel.kptr_restrict >= 1` | Hides kernel addresses that help exploit development. |
| KRN-04 | `kernel.dmesg_restrict = 1` | Keeps kernel logs away from unprivileged users. |
| FIL-01 | `/etc/passwd` mode 644 or stricter | Must be readable, never writable by non-root. |
| FIL-02 | `/etc/shadow` mode 640 or stricter | Holds password hashes. |
| FIL-03 | `/etc/ssh/sshd_config` mode 600 | Daemon configuration should be root-only. |

## Not covered yet

Firewall policy, auditd rules, PAM password policy, automatic security updates, filesystem mount options, and disabling unused services. These are good next additions.
