import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


try:
    import fcntl  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - Windows test runner compatibility
    sys.modules["fcntl"] = types.ModuleType("fcntl")
try:
    import pwd  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - Windows test runner compatibility
    sys.modules["pwd"] = types.ModuleType("pwd")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backupscript"))

import backup_job  # noqa: E402


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


CRONTAB = "# m h dom mon dow command\n\n0 3 * * * /usr/local/bin/job\n  # indented comment\n*/5 * * * * /bin/true\n"


class CrontabBackupTests(unittest.TestCase):
    def backup(self, enabled=True, installed=True, listing=None):
        cfg = {"backup": {"crontab_enabled": enabled}}
        recorded = []

        def record(cfg, producer, destination, attempts, **kwargs):
            recorded.append((producer, destination))

        with mock.patch.object(backup_job, "command_exists", return_value=installed), \
                mock.patch.object(backup_job, "run", return_value=listing or completed(stdout=CRONTAB)) as run, \
                mock.patch.object(backup_job, "stream_compressed", record), \
                mock.patch.object(backup_job, "remote_file_size", return_value=42):
            report = backup_job.backup_crontab(cfg, "/run")
        return report, recorded, run

    def test_root_crontab_is_streamed_into_the_run(self):
        report, recorded, run = self.backup()
        self.assertEqual(recorded, [(["crontab", "-u", "root", "-l"], "/run/system/root-crontab.txt.zst")])
        self.assertEqual(run.call_args.args[0], ["crontab", "-u", "root", "-l"])
        self.assertEqual(
            report,
            {"enabled": True, "available": True, "present": True, "entry_count": 2, "compressed_bytes": 42},
        )

    def test_disabled_policy_does_not_touch_cron(self):
        report, recorded, run = self.backup(enabled=False)
        run.assert_not_called()
        self.assertEqual(recorded, [])
        self.assertFalse(report["enabled"])

    def test_host_without_crontab_program_is_reported_not_failed(self):
        report, recorded, _run = self.backup(installed=False)
        self.assertEqual(recorded, [])
        self.assertTrue(report["enabled"])
        self.assertFalse(report["available"])

    def test_root_without_crontab_has_nothing_to_save(self):
        report, recorded, _run = self.backup(listing=completed(1, stderr="no crontab for root\n"))
        self.assertEqual(recorded, [])
        self.assertTrue(report["available"])
        self.assertFalse(report["present"])

    def test_any_other_crontab_failure_fails_the_run(self):
        with self.assertRaises(RuntimeError):
            self.backup(listing=completed(2, stderr="permission denied"))

    def test_a_missing_setting_defaults_to_enabled(self):
        with mock.patch.object(backup_job, "command_exists", return_value=False):
            report = backup_job.backup_crontab({"backup": {}}, "/run")
        self.assertTrue(report["enabled"])

    def test_policy_snapshot_switches_crontab(self):
        cfg = {"backup": {"mariadb_available": False}}
        policy = {"id": 1, "name": "Standard", "paths": []}
        backup_job.apply_command_policy(cfg, {"policy": dict(policy, crontab_enabled=False)})
        self.assertFalse(cfg["backup"]["crontab_enabled"])
        backup_job.apply_command_policy(cfg, {"policy": policy})
        self.assertTrue(cfg["backup"]["crontab_enabled"])


if __name__ == "__main__":
    unittest.main()
