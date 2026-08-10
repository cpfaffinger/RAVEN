import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))

import mirror  # noqa: E402


class RsyncOptionTests(unittest.TestCase):
    def test_accepts_the_common_transfer_flags(self):
        self.assertEqual(
            mirror.validated_rsync_options("-avz --delete --stats"),
            ["-avz", "--delete", "--stats"],
        )
        self.assertEqual(
            mirror.validated_rsync_options("--archive --bwlimit=50M --exclude=current/"),
            ["--archive", "--bwlimit=50M", "--exclude=current/"],
        )

    def test_rejects_options_that_run_commands(self):
        for raw in (
            "-a -e 'ssh -o ProxyCommand=curl evil'",
            "-a --rsh=/bin/sh",
            "-a --rsync-path='rm -rf /'",
            "-a -M--log-file=/etc/passwd",
            "-a --files-from=/etc/shadow",
        ):
            with self.assertRaises(ValueError, msg=raw):
                mirror.validated_rsync_options(raw)

    def test_accepts_protect_rules_that_keep_history(self):
        self.assertEqual(
            mirror.validated_rsync_options(mirror.HISTORY_RSYNC_OPTIONS),
            ["-a", "--delete", "--stats", "--filter=P backup_*/[0-9]*"],
        )
        self.assertEqual(
            mirror.validated_rsync_options("--filter='- *.tmp'"), ["--filter=- *.tmp"]
        )

    def test_rejects_filter_rules_that_read_files(self):
        for raw in (
            "--filter='merge /etc/shadow'",
            "--filter='. /etc/passwd'",
            "--filter='dir-merge .rules'",
            "--filter='P $(reboot)'",
        ):
            with self.assertRaises(ValueError, msg=raw):
                mirror.validated_rsync_options(raw)

    def test_rejects_unknown_flags_and_bare_paths(self):
        for raw in ("-a --make-it-so", "-a /etc/passwd", "-aQ"):
            with self.assertRaises(ValueError, msg=raw):
                mirror.validated_rsync_options(raw)

    def test_rejects_shell_metacharacters_in_values(self):
        with self.assertRaises(ValueError):
            mirror.validated_rsync_options("--exclude=$(reboot)")


class ScopeTests(unittest.TestCase):
    def test_only_the_backup_accounts_take_part(self):
        self.assertEqual(
            mirror.scope_filters("backup_"), ["--filter=+ /backup_*/", "--filter=- /*"]
        )
        self.assertEqual(
            mirror.scope_filters("raven_"), ["--filter=+ /raven_*/", "--filter=- /*"]
        )

    def test_scope_rules_leave_the_content_of_an_account_alone(self):
        # No rule carries "**", so operator rules still decide inside an account.
        for rule in mirror.scope_filters("backup_"):
            self.assertNotIn("**", rule)

    def test_scope_rejects_an_unusable_prefix(self):
        for prefix in ("Backup_", "back up", "*", ""):
            with self.assertRaises(ValueError, msg=prefix):
                mirror.scope_filters(prefix)

    def test_scope_rules_follow_the_operator_options(self):
        command = mirror.rsync_command(
            source_path="/home", username="m", host="h", remote_path="/srv/x",
            options=["-a", "--exclude=*.tmp"], key_path="/k", known_hosts_path="/kh",
            port=22, account_prefix="backup_",
        )
        self.assertLess(command.index("--exclude=*.tmp"), command.index("--filter=+ /backup_*/"))

    def test_foreign_entries_are_only_listed(self):
        command = mirror.foreign_entries_command("/srv/raven", "backup_")
        self.assertIn("-mindepth 1 -maxdepth 1", command)
        self.assertIn("! -name 'backup_*'", command)
        self.assertNotIn("rm", command)


class CommandTests(unittest.TestCase):
    def test_rsync_command_pins_the_transport(self):
        command = mirror.rsync_command(
            source_path="/home", username="mirror", host="mirror.example.com",
            remote_path="/srv/raven", options=["-a", "--delete"],
            key_path="/run/key", known_hosts_path="/run/known", port=2222,
            account_prefix="backup_",
        )
        self.assertEqual(command[0], "/usr/bin/rsync")
        self.assertEqual(command[-2], "/home/")
        self.assertEqual(command[-1], "mirror@mirror.example.com:/srv/raven/")
        transport = command[command.index("-e") + 1]
        self.assertIn("StrictHostKeyChecking=yes", transport)
        self.assertIn("UserKnownHostsFile=/run/known", transport)
        self.assertIn("-p 2222", transport)

    def test_disk_usage_parsing(self):
        output = (
            "Filesystem     1B-blocks         Used    Available Capacity Mounted on\n"
            "/dev/sda1   983349825536 703348736000 280001089536      72% /srv\n"
        )
        self.assertEqual(mirror.parse_disk_usage(output), (983349825536, 280001089536))

    def test_disk_usage_rejects_garbage(self):
        with self.assertRaises(ValueError):
            mirror.parse_disk_usage("df: /srv: No such file or directory\n")

    def test_transferred_bytes_from_stats(self):
        self.assertEqual(
            mirror.parse_transferred_bytes("Total transferred file size: 1,234,567 bytes\n"),
            1234567,
        )
        self.assertEqual(mirror.parse_transferred_bytes("sent 4096 bytes  received 12 bytes\n"), 4096)
        self.assertIsNone(mirror.parse_transferred_bytes("nichts davon"))


class RetentionTests(unittest.TestCase):
    def test_prune_only_matches_run_directories(self):
        command = mirror.retention_command("/srv/raven", 8)
        self.assertIn("-mindepth 2 -maxdepth 2", command)
        self.assertIn("backup_[^/]+/[0-9]{8,20}", command)
        self.assertIn("-mtime +8", command)
        self.assertTrue(command.startswith("find /srv/raven "))

    def test_prune_refuses_unsafe_input(self):
        with self.assertRaises(ValueError):
            mirror.retention_command("/srv/raven", 0)
        with self.assertRaises(ValueError):
            mirror.retention_command("/srv/../etc; rm -rf /", 8)


class ValidationTests(unittest.TestCase):
    def base(self, **overrides):
        values = {
            "host": "Mirror.Example.COM", "username": "mirror", "remote_path": "/srv/raven/",
            "ssh_port": "2222", "interval_hours": "24", "retention_days": "30",
            "rsync_options": "-a --delete",
        }
        values.update(overrides)
        return mirror.validated_target(**values)

    def test_normalises_and_accepts(self):
        target = self.base()
        self.assertEqual(target["host"], "mirror.example.com")
        self.assertEqual(target["remote_path"], "/srv/raven")
        self.assertEqual(target["ssh_port"], 2222)
        self.assertEqual(target["rsync_options"], "-a --delete")

    def test_rejects_impossible_values(self):
        for overrides in (
            {"host": "not a host"},
            {"username": "Root Admin"},
            {"remote_path": "relative/path"},
            {"remote_path": "/"},
            {"ssh_port": "0"},
            {"interval_hours": "0"},
            {"retention_days": "-1"},
        ):
            with self.assertRaises(ValueError, msg=str(overrides)):
                self.base(**overrides)


class KeyTests(unittest.TestCase):
    def test_accepts_openssh_key(self):
        raw = "-----BEGIN OPENSSH PRIVATE KEY-----\r\nabc\r\n-----END OPENSSH PRIVATE KEY-----"
        self.assertTrue(mirror.normalized_private_key(raw).endswith("-----\n"))
        self.assertNotIn("\r", mirror.normalized_private_key(raw))

    def test_rejects_anything_else(self):
        for raw in ("ssh-ed25519 AAAA...", "", "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"):
            with self.assertRaises(ValueError):
                mirror.normalized_private_key(raw)

    def test_host_key_is_pinned_to_the_address(self):
        scanned = "mirror.example.com ssh-ed25519 AAAAC3Nz\n# comment\n"
        self.assertEqual(
            mirror.normalized_host_key(scanned, "mirror.example.com", 2222),
            "[mirror.example.com]:2222 ssh-ed25519 AAAAC3Nz\n",
        )
        self.assertEqual(
            mirror.normalized_host_key(scanned, "mirror.example.com", 22),
            "mirror.example.com ssh-ed25519 AAAAC3Nz\n",
        )

    def test_host_key_requires_content(self):
        with self.assertRaises(ValueError):
            mirror.normalized_host_key("# nur ein Kommentar\n", "mirror.example.com", 22)


if __name__ == "__main__":
    unittest.main()
