import unittest

from hardening_audit import (Check, check_modes, check_ssh, check_sysctl,
                             merge_configs, parse_sshd, score)

GOOD_SSH = """
# comment
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
"""


def by_id(checks):
    return {c.id: c for c in checks}


class ParseTests(unittest.TestCase):
    def test_first_occurrence_wins(self):
        cfg = parse_sshd("PermitRootLogin no\nPermitRootLogin yes\n")
        self.assertEqual(cfg["permitrootlogin"], "no")

    def test_stops_at_match_block(self):
        cfg = parse_sshd("X11Forwarding no\nMatch User bob\n  PasswordAuthentication yes\n")
        self.assertNotIn("passwordauthentication", cfg)

    def test_dropin_overrides_main_when_read_first(self):
        merged = merge_configs([parse_sshd("PasswordAuthentication no"),
                                parse_sshd("PasswordAuthentication yes")])
        self.assertEqual(merged["passwordauthentication"], "no")


class SshTests(unittest.TestCase):
    def test_hardened_config_passes(self):
        results = check_ssh(parse_sshd(GOOD_SSH))
        self.assertTrue(all(c.status == "PASS" for c in results))

    def test_missing_setting_fails(self):
        results = by_id(check_ssh({}))
        self.assertEqual(results["SSH-01"].status, "FAIL")

    def test_weak_values_fail(self):
        cfg = parse_sshd("PermitRootLogin yes\nMaxAuthTries 10\n")
        results = by_id(check_ssh(cfg))
        self.assertEqual(results["SSH-01"].status, "FAIL")
        self.assertEqual(results["SSH-05"].status, "FAIL")


class SysctlTests(unittest.TestCase):
    def test_pass_fail_and_skip(self):
        results = by_id(check_sysctl({
            "net.ipv4.ip_forward": "1",
            "kernel.randomize_va_space": "2",
        }))
        self.assertEqual(results["NET-01"].status, "FAIL")
        self.assertEqual(results["KRN-01"].status, "PASS")
        self.assertEqual(results["NET-06"].status, "SKIP")


class ModeTests(unittest.TestCase):
    def test_strict_modes_pass(self):
        results = by_id(check_modes({"/etc/passwd": 0o644, "/etc/shadow": 0o640,
                                     "/etc/ssh/sshd_config": 0o600}))
        self.assertTrue(all(c.status == "PASS" for c in results.values()))

    def test_world_readable_shadow_fails(self):
        results = by_id(check_modes({"/etc/shadow": 0o644}))
        self.assertEqual(results["FIL-02"].status, "FAIL")

    def test_shadow_000_passes(self):
        results = by_id(check_modes({"/etc/shadow": 0o000}))
        self.assertEqual(results["FIL-02"].status, "PASS")


class ScoreTests(unittest.TestCase):
    def test_skips_are_not_scored(self):
        checks = [Check("a", "", "PASS", ""), Check("b", "", "FAIL", ""), Check("c", "", "SKIP", "")]
        self.assertEqual(score(checks), 50)

    def test_empty_is_zero(self):
        self.assertEqual(score([]), 0)


if __name__ == "__main__":
    unittest.main()
