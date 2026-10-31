import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from portal_harness import PortalTestCase, hours_ahead, portal_core as core, portal_workers as workers  # noqa: E402


GIB = 1024**3
RSYNC_STATS = """Number of files: 12
Literal data: 1,234,567 bytes
Matched data: 42 bytes
Total transferred file size: 9,999,999 bytes
sent 1,300,000 bytes  received 4,000 bytes  2,000.00 bytes/sec
"""


class FakeRemote:
    """Answer the ssh commands of a replication the way the mirror host would."""

    def __init__(self, *, free=500 * GIB, seed_output="", prune_output="", foreign_output=""):
        self.free = free
        self.seed_output = seed_output
        self.prune_output = prune_output
        self.foreign_output = foreign_output
        self.commands = []

    def __call__(self, command, **_kwargs):
        remote = command[-1]
        self.commands.append(remote)
        stdout = ""
        if remote.startswith("df "):
            stdout = (
                "Filesystem 1-blocks Used Available Capacity Mounted\n"
                f"/dev/sdb1 {1000 * GIB} {1000 * GIB - self.free} {self.free} 50% /srv\n"
            )
        elif "seed()" in remote:
            stdout = self.seed_output
        elif "-mtime" in remote:
            stdout = self.prune_output
        elif "-printf" in remote:
            stdout = self.foreign_output
        return subprocess.CompletedProcess(command, 0, stdout, "")

    def ran(self, marker):
        return [command for command in self.commands if marker in command]


class MirrorRunTestCase(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.remote = FakeRemote()
        self.subprocess_run.side_effect = self.remote
        self.streaming = self.patch(workers, "run_streaming", return_value=(0, RSYNC_STATS))
        self.rsync = self.patch(workers.mirror_module, "rsync_command", wraps=workers.mirror_module.rsync_command)
        self.add_backup_run("backup_alpha", "20261030020000", complete=True)
        self.add_backup_run("backup_alpha", "20261031020000", complete=False)
        self.add_backup_run("backup_beta", "20261031020000", complete=False)
        (core.HOME_ROOT / "lost+found").mkdir()

    def add_backup_run(self, account, run, *, complete):
        directory = core.HOME_ROOT / account / run
        directory.mkdir(parents=True)
        if complete:
            (directory / ".backup-ok").touch()

    def replicate(self, **target_columns):
        """Queue a run for a new target and execute it the way the mirror worker does."""
        target_id = self.add_mirror_target(**target_columns)
        run_id = self.add_mirror_run(target_id, "queued")
        run = workers.claim_mirror_run()
        self.assertEqual(run["id"], run_id)
        workers.execute_mirror_run(run)
        return (
            self.row("SELECT * FROM mirror_runs WHERE id=?", run_id),
            self.row("SELECT * FROM mirror_targets WHERE id=?", target_id),
        )


class LatestStrategyTests(MirrorRunTestCase):
    def test_passes_the_newest_complete_run_of_every_account_into_rsync(self):
        run, _target = self.replicate(strategy="latest")
        self.assertEqual(run["status"], "success")
        self.assertEqual(
            self.rsync.call_args.kwargs["selection"],
            {"backup_alpha": "20261030020000", "backup_beta": None},
        )

    def test_the_selection_reaches_the_command_that_is_executed(self):
        self.replicate(strategy="latest")
        command = self.streaming.call_args.args[0]
        self.assertIn("--filter=+ /backup_alpha/20261030020000/", command)
        self.assertIn("--filter=- /backup_beta/", command)
        self.assertIn("--delete-after", command)
        self.assertNotIn("--delete", command)

    def test_skips_retention_pruning_even_with_a_retention_configured(self):
        self.remote.prune_output = "/srv/raven/backup_alpha/20250101000000\n"
        run, _target = self.replicate(strategy="latest", retention_days=30)
        self.assertEqual(self.remote.ran("-mtime"), [])
        self.assertEqual(run["status"], "success")
        self.assertNotIn("Aufbewahrung", run["output"])

    def test_seeds_the_new_run_on_the_mirror_before_the_transfer(self):
        self.remote.seed_output = "backup_alpha: 20261029020000 -> 20261030020000\n"
        run, _target = self.replicate(strategy="latest")
        seeds = self.remote.ran("seed()")
        self.assertEqual(len(seeds), 1)
        self.assertIn("seed backup_alpha 20261030020000", seeds[0])
        self.assertNotIn("seed backup_beta", seeds[0])
        self.assertIn("Als Basis vom vorherigen Stand übernommen (1)", run["output"])

    def test_names_an_account_without_a_complete_run_in_the_output(self):
        run, _target = self.replicate(strategy="latest")
        self.assertIn("backup_alpha: 20261030020000", run["output"])
        self.assertIn("backup_beta: kein vollständiger Lauf", run["output"])


class FullStrategyTests(MirrorRunTestCase):
    def test_transfers_without_a_selection(self):
        self.replicate(strategy="full")
        self.assertIsNone(self.rsync.call_args.kwargs["selection"])
        self.assertEqual(self.remote.ran("seed()"), [])

    def test_prunes_by_retention_after_a_good_transfer(self):
        self.remote.prune_output = "/srv/raven/backup_alpha/20250101000000\n"
        run, _target = self.replicate(strategy="full", retention_days=30)
        prunes = self.remote.ran("-mtime")
        self.assertEqual(len(prunes), 1)
        self.assertIn("-mtime +30", prunes[0])
        self.assertIn("Aufbewahrung 30 Tage: 1 Laeufe entfernt", run["output"])

    def test_keeps_every_run_without_a_retention(self):
        self.replicate(strategy="full", retention_days=0)
        self.assertEqual(self.remote.ran("-mtime"), [])


class TransferResultTests(MirrorRunTestCase):
    def test_a_non_zero_rsync_status_ends_in_failure(self):
        self.streaming.return_value = (23, "rsync error: some files could not be transferred\n")
        run, target = self.replicate(next_run_at=hours_ahead(216))
        self.assertEqual(run["status"], "failure")
        self.assertEqual(run["exit_code"], 23)
        self.assertEqual(run["summary"], "rsync endete mit Status 23")
        self.assertIn("rsync error", run["output"])
        self.assertIsNotNone(run["finished_at"])
        self.assertEqual(target["last_status"], "failure")
        self.assertEqual(target["last_message"], "rsync endete mit Status 23")

    def test_a_failed_transfer_pulls_the_retry_forward(self):
        self.streaming.return_value = (12, "")
        _run, target = self.replicate(next_run_at=hours_ahead(216))
        retry = datetime.fromisoformat(target["next_run_at"]) - datetime.now(timezone.utc)
        self.assertLess(abs(retry - timedelta(hours=workers.MIRROR_RETRY_HOURS)), timedelta(minutes=1))

    def test_a_failed_transfer_neither_prunes_nor_lists_foreign_entries(self):
        self.streaming.return_value = (12, "")
        self.replicate(strategy="full", retention_days=30)
        self.assertEqual(self.remote.ran("-mtime"), [])
        self.assertEqual(self.remote.ran("-printf"), [])

    def test_a_file_that_vanished_mid_transfer_counts_as_success(self):
        self.streaming.return_value = (24, RSYNC_STATS)
        run, target = self.replicate()
        self.assertEqual(run["status"], "success")
        self.assertEqual(run["exit_code"], 24)
        self.assertEqual(target["last_status"], "success")

    def test_success_records_the_transferred_bytes_from_literal_data(self):
        run, target = self.replicate()
        self.assertEqual(run["status"], "success")
        self.assertEqual(run["exit_code"], 0)
        self.assertEqual(run["transferred_bytes"], 1_234_567)
        self.assertIn(core.format_size(1_234_567), run["summary"])
        self.assertEqual(target["last_message"], run["summary"])

    def test_success_leaves_the_regular_schedule_alone(self):
        next_run_at = hours_ahead(216)
        _run, target = self.replicate(next_run_at=next_run_at)
        self.assertEqual(target["next_run_at"], next_run_at)

    def test_success_records_no_byte_count_without_statistics(self):
        self.streaming.return_value = (0, "")
        run, _target = self.replicate()
        self.assertEqual(run["status"], "success")
        self.assertIsNone(run["transferred_bytes"])

    def test_reports_what_stayed_on_the_mirror_outside_the_accounts(self):
        self.remote.foreign_output = "old-data\nnotes.txt\n"
        run, _target = self.replicate()
        self.assertIn("weiterhin auf dem Ziel vorhanden (2): old-data, notes.txt", run["output"])

    def test_stores_the_disk_usage_of_the_target(self):
        self.remote.free = 123 * GIB
        _run, target = self.replicate()
        self.assertEqual(target["free_bytes"], 123 * GIB)
        self.assertEqual(target["total_bytes"], 1000 * GIB)
        self.assertIsNotNone(target["space_checked_at"])

    def test_publishes_progress_while_the_transfer_runs(self):
        seen = []

        def transfer(_command, _timeout, publish):
            publish("to-chk=5/12")
            seen.append(self.row("SELECT output FROM mirror_runs ORDER BY id DESC LIMIT 1")["output"])
            return 0, RSYNC_STATS

        self.streaming.side_effect = transfer
        self.replicate()
        self.assertIn("to-chk=5/12", seen[0])


class RefusedRunTests(MirrorRunTestCase):
    def test_a_full_target_is_not_replicated_to(self):
        self.remote.free = workers.MIRROR_MIN_FREE_BYTES - 1
        run, target = self.replicate()
        self.streaming.assert_not_called()
        self.assertEqual(run["status"], "failure")
        self.assertIn("ist voll", run["summary"])
        self.assertEqual(target["last_status"], "failure")

    def test_an_unreadable_disk_usage_does_not_stop_the_transfer(self):
        def remote(command, **kwargs):
            if command[-1].startswith("df "):
                return subprocess.CompletedProcess(command, 1, "", "permission denied")
            return self.remote(command, **kwargs)

        self.subprocess_run.side_effect = remote
        run, _target = self.replicate()
        self.assertEqual(run["status"], "success")
        self.assertIn("Zielspeicher konnte nicht gelesen werden: permission denied", run["output"])

    def test_forbidden_rsync_options_fail_before_any_credential_is_written(self):
        run, _target = self.replicate(rsync_options="-a --rsh=/bin/sh")
        self.assertEqual(run["status"], "failure")
        self.assertEqual(run["exit_code"], 2)
        self.assertEqual(self.remote.commands, [])
        self.streaming.assert_not_called()
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_a_target_deleted_after_the_claim_ends_quietly(self):
        target_id = self.add_mirror_target()
        self.add_mirror_run(target_id, "queued")
        run = workers.claim_mirror_run()
        self.execute("DELETE FROM mirror_targets WHERE id=?", target_id)
        workers.execute_mirror_run(run)
        self.streaming.assert_not_called()
        self.assertEqual(self.count("mirror_runs"), 0)


class FailedRunTests(MirrorRunTestCase):
    def test_a_timeout_is_recorded_with_the_partial_output(self):
        self.streaming.side_effect = subprocess.TimeoutExpired("rsync", 1, output=b"partial transfer")
        run, target = self.replicate(next_run_at=hours_ahead(216))
        self.assertEqual(run["status"], "failure")
        self.assertEqual(run["exit_code"], 124)
        self.assertIn("Zeitlimit", run["summary"])
        self.assertIn("partial transfer", run["output"])
        self.assertEqual(target["last_status"], "failure")

    def test_an_unexpected_error_does_not_leave_the_run_running(self):
        self.streaming.side_effect = OSError("rsync is gone")
        run, _target = self.replicate()
        self.assertEqual(run["status"], "failure")
        self.assertEqual(run["exit_code"], 2)
        self.assertEqual(run["summary"], "OSError: rsync is gone")

    def test_credentials_are_removed_after_every_outcome(self):
        outcomes = {
            "success": lambda: None,
            "rsync failure": lambda: setattr(self.streaming, "return_value", (23, "")),
            "exception": lambda: setattr(self.streaming, "side_effect", OSError("gone")),
        }
        for index, (name, arrange) in enumerate(outcomes.items()):
            with self.subTest(name):
                arrange()
                self.replicate(name=f"box{index}")
                self.assertEqual(list(self.scratch.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
