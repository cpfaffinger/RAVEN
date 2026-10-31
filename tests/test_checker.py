import contextlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


try:
    import pwd  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - Windows test runner compatibility
    sys.modules["pwd"] = types.ModuleType("pwd")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import backup_check  # noqa: E402


# Mid-July and mid-day keep the naive run names clear of any DST switch.
NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc).astimezone()
MARKER = ".backup-ok"


class CheckerTestCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temp = Path(temporary.name)
        self.home_root = self.temp / "home"
        self.home_root.mkdir()
        self.state_path = self.temp / "state.json"
        self.now = NOW
        self.cfg = {
            "monitor": {
                "home_root": str(self.home_root),
                "user_glob": "backup_*",
                "max_age_hours": 36,
                # Same list as install.sh: the 17-digit run ids need %f.
                "timestamp_formats": ["%Y%m%d", "%Y%m%d%H%M", "%Y%m%d%H%M%S", "%Y%m%d%H%M%S%f"],
                "require_ok_file_for_users": ["backup_*"],
                "ok_marker_name": MARKER,
                "incomplete_grace_hours": 6,
                "check_volume_change": False,
                "ssh_activity_for_mirrors": False,
                "volume_timeout_seconds": 1,
            },
            "smtp": {"enabled": True},
            "alerts": {"state_file": str(self.state_path), "reminder_hours": 24},
            "storage": {"enabled": False},
        }
        self.start(mock.patch.object(backup_check, "local_now", side_effect=lambda: self.now))
        self.getpwnam = self.start(
            mock.patch.object(backup_check.pwd, "getpwnam", side_effect=self.account, create=True)
        )

    def start(self, patcher):
        self.addCleanup(patcher.stop)
        return patcher.start()

    def account(self, name):
        path = self.home_root / name
        if not path.is_dir():
            raise KeyError(name)
        return types.SimpleNamespace(pw_dir=str(path), pw_uid=path.stat().st_uid)

    def home(self, name="backup_web"):
        path = self.home_root / name
        path.mkdir(exist_ok=True)
        return path

    def run_name(self, hours_ago):
        return (self.now - timedelta(hours=hours_ago)).astimezone().strftime("%Y%m%d%H%M%S") + "000"

    def marked_run(self, home, hours_ago):
        run = home / self.run_name(hours_ago)
        run.mkdir()
        marker = run / MARKER
        marker.write_text(json.dumps({"status": "ok", "run_id": run.name}), encoding="utf-8")
        finished = (self.now - timedelta(hours=hours_ago)).timestamp()
        os.utime(marker, (finished, finished))
        return run

    def unmarked_run(self, home, hours_ago, marker_bytes=None):
        run = home / self.run_name(hours_ago)
        run.mkdir()
        (run / "manifest.json").write_text("{}", encoding="utf-8")
        if marker_bytes is not None:
            (run / MARKER).write_bytes(marker_bytes)
        touched = (self.now - timedelta(hours=hours_ago)).timestamp()
        os.utime(run, (touched, touched))
        return run

    def evaluate_one(self):
        results = backup_check.evaluate(self.cfg)
        self.assertEqual(len(results), 1)
        return results[0]


class EvaluateTests(CheckerTestCase):
    def test_a_fresh_run_with_a_valid_marker_is_ok(self):
        run = self.marked_run(self.home(), 2)
        result = self.evaluate_one()
        self.assertEqual((result.user, result.status, result.mode), ("backup_web", "OK", "timestamped"))
        self.assertEqual(result.age_hours, 2)
        self.assertIn(run.name, result.detail)

    def test_a_run_older_than_the_max_age_alarms(self):
        self.marked_run(self.home(), 37)
        result = self.evaluate_one()
        self.assertEqual(result.status, "STALE")
        self.assertEqual(result.age_hours, 37)

    def test_a_run_just_inside_the_max_age_is_ok(self):
        self.marked_run(self.home(), 35)
        self.assertEqual(self.evaluate_one().status, "OK")

    def test_a_run_without_marker_is_not_counted(self):
        self.unmarked_run(self.home(), 2)
        result = self.evaluate_one()
        self.assertEqual(result.status, "STALE")
        self.assertIsNone(result.latest)
        self.assertIn("kein vollstaendiger", result.detail)

    def test_an_unmarked_run_does_not_shadow_the_last_complete_one(self):
        home = self.home()
        self.marked_run(home, 20)
        self.unmarked_run(home, 2)
        result = self.evaluate_one()
        self.assertEqual(result.status, "OK")
        self.assertEqual(result.age_hours, 20)

    def test_an_unmarked_newest_run_alarms_after_the_grace_period(self):
        home = self.home()
        self.marked_run(home, 20)
        self.unmarked_run(home, 7)
        result = self.evaluate_one()
        self.assertEqual(result.status, "ERROR")
        self.assertIn("unvollstaendig", result.detail)

    def test_ignored_accounts_are_skipped(self):
        self.marked_run(self.home("backup_web"), 2)
        self.home("backup_archive")  # no system account: would be an ERROR if it were looked at
        self.cfg["monitor"]["ignore"] = ["backup_archive"]
        self.assertEqual([result.user for result in backup_check.evaluate(self.cfg)], ["backup_web"])
        self.assertNotIn(mock.call("backup_archive"), self.getpwnam.call_args_list)

    def test_a_home_without_system_account_alarms(self):
        self.home("backup_web")
        self.getpwnam.side_effect = KeyError("backup_web")
        result = self.evaluate_one()
        self.assertEqual((result.status, result.mode), ("ERROR", "account"))

    def test_a_corrupt_marker_does_not_count(self):
        name = self.run_name(2)
        cases = {
            "not json": b"{broken",
            "not utf-8": b"\xff\xfe\xff",
            "not an object": b"[]",
            "null": b"null",
            "wrong status": json.dumps({"status": "failed", "run_id": name}).encode(),
            "other run id": json.dumps({"status": "ok", "run_id": "20200101000000000"}).encode(),
        }
        for label, content in cases.items():
            with self.subTest(label):
                home = self.home("backup_case")
                self.unmarked_run(home, 2, marker_bytes=content)
                result = self.evaluate_one()
                self.assertEqual(result.status, "STALE")
                self.assertIsNone(result.latest)
                (home / name / MARKER).unlink()
                (home / name / "manifest.json").unlink()
                (home / name).rmdir()


class RetentionTests(CheckerTestCase):
    def setUp(self):
        super().setUp()
        self.cfg["cleanup"] = {
            "enabled": True,
            "snapshot_name_digits": 17,
            "snapshot_retention_days": 7,
            "minimum_snapshots_to_keep": 2,
            "incomplete_snapshot_retention_hours": 48,
            "legacy_file_retention_days": 5,
        }
        self.measure = self.start(
            mock.patch.object(backup_check, "measure_volume_bytes", return_value=1000)
        )

    def cleanup(self, *, dry_run=False):
        return backup_check.cleanup_backups(self.cfg, dry_run=dry_run, ignore_run_hour=True)

    def test_the_newest_marked_runs_stay_even_when_expired(self):
        home = self.home()
        oldest = self.marked_run(home, 30 * 24)
        middle = self.marked_run(home, 20 * 24)
        newest = self.marked_run(home, 10 * 24)
        result = self.cleanup()
        self.assertEqual(result.status, "OK")
        self.assertFalse(oldest.exists())
        self.assertTrue(middle.exists())
        self.assertTrue(newest.exists())
        self.assertIn("1 erfolgreiche Snapshots", result.detail)
        self.assertEqual(result.volume_bytes, 1000)

    def test_only_expired_runs_beyond_the_minimum_go(self):
        home = self.home()
        expired = self.marked_run(home, 8 * 24)
        kept = [self.marked_run(home, days * 24) for days in (6, 2, 1)]
        self.cleanup()
        self.assertFalse(expired.exists())
        self.assertTrue(all(run.exists() for run in kept))

    def test_incomplete_runs_go_only_after_the_limit(self):
        home = self.home()
        self.marked_run(home, 24)
        old = self.unmarked_run(home, 49)
        young = self.unmarked_run(home, 47)
        result = self.cleanup()
        self.assertFalse(old.exists())
        self.assertTrue(young.exists())
        self.assertIn("1 unvollstaendige", result.detail)

    def test_a_corrupt_marker_gets_no_protected_slot(self):
        self.cfg["cleanup"]["minimum_snapshots_to_keep"] = 1
        name = self.run_name(72)
        cases = {
            "backup_broken": b"{broken",
            "backup_failed": json.dumps({"status": "failed", "run_id": name}).encode(),
            "backup_foreign": json.dumps({"status": "ok", "run_id": "20200101000000000"}).encode(),
        }
        for user, content in cases.items():
            with self.subTest(user):
                home = self.home(user)
                older = self.marked_run(home, 30 * 24)
                last_complete = self.marked_run(home, 20 * 24)
                corrupt = self.unmarked_run(home, 72, marker_bytes=content)
                self.cleanup()
                self.assertFalse(corrupt.exists())
                self.assertFalse(older.exists())
                self.assertTrue(last_complete.exists())

    def test_dry_run_deletes_nothing_but_reports_the_same(self):
        home = self.home()
        runs = [self.marked_run(home, days * 24) for days in (30, 20, 10)]
        incomplete = self.unmarked_run(home, 72)
        legacy = home / "old.sql"
        legacy.write_text("dump", encoding="utf-8")
        old = (self.now - timedelta(days=30)).timestamp()
        os.utime(legacy, (old, old))
        empty = home / "empty"
        empty.mkdir()

        result = self.cleanup(dry_run=True)

        self.assertTrue(all(run.exists() for run in runs))
        self.assertTrue(incomplete.exists())
        self.assertTrue(legacy.exists())
        self.assertTrue(empty.exists())
        self.assertIn("Cleanup-Dry-Run", result.detail)
        self.assertIn("1 erfolgreiche Snapshots, 1 unvollstaendige", result.detail)
        self.assertEqual(result.volume_bytes, 2000 + len("dump"))

    def test_an_invalid_retention_is_an_error_and_deletes_nothing(self):
        home = self.home()
        self.cfg["cleanup"]["policy_by_user"] = {"backup_web": {"enabled": True, "retention_days": 0}}
        runs = [self.marked_run(home, days * 24) for days in (30, 20, 10)]
        result = self.cleanup()
        self.assertEqual(result.status, "ERROR")
        self.assertTrue(all(run.exists() for run in runs))

    def test_old_dumps_in_the_current_mirror_survive(self):
        # The legacy sweep must stay out of current/, or
        # a synced *.sql or *.gz whose source mtime is older than
        # legacy_file_retention_days disappears from the mirror every night,
        # although the manual promises that retention never touches current/.
        synced = self.home() / "current" / "www"
        synced.mkdir(parents=True)
        dump = synced / "shop.sql"
        dump.write_text("dump", encoding="utf-8")
        old = (self.now - timedelta(days=30)).timestamp()
        os.utime(dump, (old, old))
        self.cleanup()
        self.assertTrue(dump.exists())


class MainTestCase(CheckerTestCase):
    def setUp(self):
        super().setUp()
        self.start(mock.patch.object(backup_check, "load_config", side_effect=lambda *_: self.cfg))
        self.start(mock.patch.object(backup_check, "CONFIG_DISPLAY", backup_check.CONFIG_DISPLAY))
        self.start(mock.patch.object(backup_check.socket, "getfqdn", return_value="target.test"))
        self.start(mock.patch.object(backup_check.socket, "gethostname", return_value="target"))
        self.send_mail = self.start(mock.patch.object(backup_check, "send_mail"))

    def check(self, *flags):
        argv = ["backup_check.py", "--config", "backup-check.toml", *flags]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            return backup_check.main()

    def state(self):
        return json.loads(self.state_path.read_text(encoding="utf-8"))["users"]

    def subjects(self):
        return [call.args[1] for call in self.send_mail.call_args_list]

    def bodies(self):
        return [call.args[2] for call in self.send_mail.call_args_list]


class NotificationTests(MainTestCase):
    def setUp(self):
        super().setUp()
        self.marked_run(self.home(), 40)

    def test_the_first_problem_notifies(self):
        self.assertEqual(self.check(), 1)
        self.assertEqual(len(self.subjects()), 1)
        self.assertIn("[Backup-ALARM]", self.subjects()[0])
        self.assertIn("[STALE] backup_web", self.bodies()[0])
        entry = self.state()["backup_web"]
        self.assertEqual(entry["status"], "STALE")
        self.assertEqual(entry["last_notice"], self.now.timestamp())

    def test_a_repeat_within_reminder_hours_stays_silent(self):
        self.check()
        first_notice = self.state()["backup_web"]["last_notice"]
        self.send_mail.reset_mock()
        self.now += timedelta(hours=23)
        self.assertEqual(self.check(), 1)
        self.send_mail.assert_not_called()
        self.assertEqual(self.state()["backup_web"]["last_notice"], first_notice)

    def test_after_reminder_hours_it_notifies_again(self):
        self.check()
        self.send_mail.reset_mock()
        self.now += timedelta(hours=24)
        self.assertEqual(self.check(), 1)
        self.assertEqual(len(self.subjects()), 1)
        self.assertIn("[Backup-ALARM]", self.subjects()[0])
        self.assertEqual(self.state()["backup_web"]["last_notice"], self.now.timestamp())

    def test_recovery_notifies_once(self):
        self.check()
        self.send_mail.reset_mock()
        self.marked_run(self.home(), 1)
        self.assertEqual(self.check(), 0)
        self.assertEqual(len(self.subjects()), 1)
        self.assertIn("wieder aktuell", self.subjects()[0])
        self.assertIn("[OK] backup_web", self.bodies()[0])

        self.send_mail.reset_mock()
        self.assertEqual(self.check(), 0)
        self.send_mail.assert_not_called()


class MirrorFileTests(MainTestCase):
    def setUp(self):
        super().setUp()
        self.marked_run(self.home(), 2)
        self.cfg["storage"] = {"enabled": True, "path": str(self.home_root)}
        self.start(
            mock.patch.object(
                backup_check.shutil, "disk_usage",
                return_value=types.SimpleNamespace(total=100, used=10, free=90),
            )
        )
        self.mirrors_file = self.temp / "mirrors.json"

    def write_mirror(self, **overrides):
        mirror = {
            "name": "box1", "interval_hours": 24, "last_status": "success", "last_message": "",
            "last_success_at": (self.now - timedelta(hours=1)).isoformat(),
        }
        mirror.update(overrides)
        self.mirrors_file.write_text(json.dumps({"mirrors": [mirror]}), encoding="utf-8")

    def check_mirrors(self, path=None):
        return self.check("--mirrors-json-file", str(path or self.mirrors_file))

    def assert_mirror_check_error(self, path=None):
        self.state_path.unlink(missing_ok=True)
        self.send_mail.reset_mock()
        self.assertEqual(self.check_mirrors(path), 1)
        users = self.state()
        self.assertEqual(users["MIRROR_CHECK"]["status"], "ERROR")
        self.assertEqual(users["MIRROR_CHECK"]["result"]["mode"], "replica")
        # The rest of the check still ran.
        self.assertEqual(users["backup_web"]["status"], "OK")
        self.assertEqual(users["BACKUP_TARGET_STORAGE"]["status"], "OK")
        self.assertEqual(len(self.subjects()), 1)
        self.assertIn("[ERROR] MIRROR_CHECK", self.bodies()[0])

    def test_a_failed_mirror_alarms_under_its_own_name(self):
        self.write_mirror(last_status="failure", last_message="rsync endete mit Status 10")
        self.assertEqual(self.check_mirrors(), 1)
        self.assertEqual(self.state()["MIRROR_box1"]["status"], "ERROR")
        self.assertEqual(len(self.subjects()), 1)
        self.assertIn("[Backup-ALARM]", self.subjects()[0])
        self.assertIn("[ERROR] MIRROR_box1", self.bodies()[0])
        self.assertIn("rsync endete mit Status 10", self.bodies()[0])

    def test_a_healthy_mirror_stays_silent(self):
        self.write_mirror()
        self.assertEqual(self.check_mirrors(), 0)
        self.assertEqual(self.state()["MIRROR_box1"]["status"], "OK")
        self.send_mail.assert_not_called()

    def test_a_missing_file_yields_a_mirror_check_error(self):
        self.assert_mirror_check_error(self.temp / "missing.json")

    def test_an_unreadable_path_yields_a_mirror_check_error(self):
        self.assert_mirror_check_error(self.temp)

    def test_invalid_content_yields_a_mirror_check_error(self):
        cases = {
            "not json": "{broken",
            "not an object": "[]",
            "oversized": json.dumps({"mirrors": [], "padding": "x" * 70000}),
            "mirror without name": json.dumps({"mirrors": [{"interval_hours": 24}]}),
            "mirrors not a list": json.dumps({"mirrors": None}),
        }
        for label, content in cases.items():
            with self.subTest(label):
                self.mirrors_file.write_text(content, encoding="utf-8")
                self.assert_mirror_check_error()

    @unittest.skipUnless(os.name == "posix", "symlinks need POSIX")
    def test_a_symlink_yields_a_mirror_check_error(self):
        self.write_mirror()
        link = self.temp / "link.json"
        link.symlink_to(self.mirrors_file)
        self.assert_mirror_check_error(link)


if __name__ == "__main__":
    unittest.main()
