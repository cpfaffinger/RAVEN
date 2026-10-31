import base64
import hashlib
import io
import json
import logging
import os
import shlex
import smtplib
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock


for module_name in ("fcntl", "pwd"):
    try:
        __import__(module_name)
    except ModuleNotFoundError:  # pragma: no cover - Windows test runner compatibility
        sys.modules[module_name] = types.ModuleType(module_name)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backupscript"))

import backup_job  # noqa: E402


STATUS_URL = "https://portal.test/api/status"
POLL_URL = "https://portal.test/api/poll"
COMMAND_URL = "https://portal.test/api/commands"
LOG_URL = "https://portal.test/api/logs"
REMOTE_HOME = "/home/backup_web"
DIGEST = "a" * 64


def finished(args="pipeline", returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args, returncode, stdout, stderr)


class FakePortal:
    """Answers urlopen, so the real payloads of every status path are recorded."""

    def __init__(self):
        self.requests = []
        self.poll_answer = {"action": "none"}

    def urlopen(self, request, timeout=None):
        self.requests.append((request.full_url, json.loads(request.data.decode("utf-8"))))
        answer = self.poll_answer if request.full_url == POLL_URL else {"ok": True}
        response = io.BytesIO(json.dumps(answer).encode("utf-8"))
        response.status = 200
        return response

    def bodies(self, url):
        return [body for target, body in self.requests if target == url]

    def commands(self):
        return [body for target, body in self.requests if target.startswith(COMMAND_URL + "/")]

    def timeline(self):
        labels = []
        for target, body in self.requests:
            if target == POLL_URL:
                labels.append("poll")
            elif target == STATUS_URL:
                labels.append(f"status:{body['event']}")
            elif target == LOG_URL:
                labels.append(f"log:{body['status']}")
            else:
                labels.append(f"command:{body['status']}")
        return labels


class FakeHost:
    """Stands in for local programs, the backup target and the stream pipeline."""

    def __init__(self):
        self.remote_commands = []
        self.written = {}
        self.write_order = []
        self.failing_prefixes = []
        self.pipelines = []
        self.pipeline_results = []
        self.du_finds_everything = False

    def subprocess_run(self, args, **kwargs):
        if args[0] == "/usr/bin/ssh" and args[1] == "-G":
            return finished(args, stdout="hostname target.test\nuser backup_web\nport 22\n")
        if args[0] == "/usr/bin/ssh":
            return self.remote_shell(args, kwargs.get("input"))
        if args[0] == "/usr/bin/du":
            path = args[-1]
            if self.du_finds_everything or Path(path).exists():
                return finished(args, stdout=f"1000\t{path}\n")
            return finished(args, 1, stderr=f"du: cannot access {path}")
        return finished(args)

    def remote_shell(self, args, input_text):
        command = args[-1]
        self.remote_commands.append(command)
        if any(command.startswith(prefix) for prefix in self.failing_prefixes):
            return finished(args, 255)
        if command.startswith("hostname;"):
            return finished(args, stdout=f"target\n{REMOTE_HOME}\n/dev/sda 1 1 {10 ** 15} 1% /\n")
        if command.startswith("du -sb"):
            return finished(args, stdout="4096\trun\n")
        if command.startswith("stat -c"):
            return finished(args, stdout="2048\n")
        if "&& mv -f" in command:
            destination = shlex.split(command)[-1]
            self.written[destination] = input_text
            self.write_order.append(destination.rsplit("/", 1)[-1])
        return finished(args)

    def run_pipeline(self, pipeline, timeout=None):
        self.pipelines.append(pipeline)
        if self.pipeline_results:
            return self.pipeline_results.pop(0)
        return finished(pipeline, stdout=f"{DIGEST}  file.partial\n")

    def markers(self):
        return [path for path in self.written if path.endswith("/.backup-ok")]


def backup_command(**overrides):
    command = {"action": "backup", "command_id": 7, "reason": "schedule", "schedule": {}}
    command.update(overrides)
    return command


class AgentTestCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "data"
        self.source.mkdir()
        self.state_path = self.root / "agent-state.json"
        self.cfg = {
            "backup": {
                "ssh_target": "backup-target",
                "expected_source_hostname": "source.test",
                "expected_ssh_hostname": "target.test",
                "expected_ssh_user": "backup_web",
                "expected_ssh_port": "22",
                "expected_remote_hostname": "target",
                "expected_remote_home": REMOTE_HOME,
                "min_remote_free_bytes": 0,
                "mariadb_enabled": False,
                "sources": [str(self.source)],
                "state_path": str(self.state_path),
                "local_lock_path": str(self.root / "agent.lock"),
                "config_version": 1,
            },
            "smtp": {},
            "status": {
                "enabled": True,
                "token": "test-token",
                "endpoint": STATUS_URL,
                "poll_endpoint": POLL_URL,
                "command_endpoint": COMMAND_URL,
                "log_endpoint": LOG_URL,
            },
            "logging": {"local_enabled": False, "portal_enabled": True},
            "notifications": {"mail_on_failure": True},
            "schedule": {"interval_hours": 24},
        }
        self.host = FakeHost()
        self.portal = FakePortal()
        self.real_acquire_lock = backup_job.acquire_local_lock

        # main() replaces the root handlers and fills the run globals.
        root_logger = logging.getLogger()
        self.addCleanup(self.restore_root_logger, list(root_logger.handlers), root_logger.level)
        quiet = logging.NullHandler()
        backup_job.LOG.addHandler(quiet)
        self.addCleanup(backup_job.LOG.removeHandler, quiet)
        for name, value in (
            ("CURRENT_PHASE", "startup"), ("CURRENT_RUN_ID", None), ("CURRENT_COMMAND_ID", None),
            ("ATTEMPT_STARTED_AT", None), ("PORTAL_LOG_HANDLER", None),
        ):
            self.start(mock.patch.object(backup_job, name, value))
        self.start(mock.patch.dict(backup_job.RUN_CONTENT_HASHES, clear=True))

        self.start(mock.patch.object(backup_job, "load_config", side_effect=lambda _: self.cfg))
        self.start(mock.patch.object(backup_job, "acquire_local_lock", return_value=mock.Mock()))
        self.start(mock.patch.object(backup_job.subprocess, "run", self.host.subprocess_run))
        self.start(mock.patch.object(backup_job, "run_pipeline", self.host.run_pipeline))
        self.start(mock.patch.object(backup_job.urllib.request, "urlopen", self.portal.urlopen))
        self.start(mock.patch.object(backup_job.socket, "getfqdn", return_value="source.test"))
        self.start(mock.patch.object(backup_job.time, "sleep"))
        self.send_mail = self.start(mock.patch.object(backup_job, "send_mail"))

    def start(self, patcher):
        self.addCleanup(patcher.stop)
        return patcher.start()

    @staticmethod
    def restore_root_logger(handlers, level):
        root_logger = logging.getLogger()
        root_logger.handlers[:] = handlers
        root_logger.setLevel(level)

    def run_main(self, *flags):
        argv = ["backup_job.py", "--config", "agent.toml", *flags]
        with mock.patch.object(sys, "argv", argv):
            return backup_job.main()

    def remember_recent_success(self):
        self.state_path.write_text(
            json.dumps({"last_success_at": datetime.now().astimezone().isoformat()}), encoding="utf-8"
        )

    def failing_run(self):
        """Run a command that dies while the size of the tar archive is read back."""
        self.host.failing_prefixes.append("stat -c")
        self.portal.poll_answer = backup_command()
        return self.run_main("--poll")


class HeldLockTests(AgentTestCase):
    def test_a_held_lock_exits_zero_without_polling(self):
        backup_job.acquire_local_lock.return_value = None
        with mock.patch.object(backup_job, "poll_portal") as poll_portal:
            self.assertEqual(self.run_main("--poll"), 0)
        poll_portal.assert_not_called()
        self.assertEqual(self.portal.requests, [])

    def test_a_held_lock_without_poll_exits_three(self):
        backup_job.acquire_local_lock.return_value = None
        with mock.patch.object(backup_job, "execute_backup") as execute_backup:
            self.assertEqual(self.run_main(), 3)
        execute_backup.assert_not_called()

    @unittest.skipUnless(hasattr(backup_job.fcntl, "flock"), "flock needs POSIX")
    def test_a_really_held_flock_exits_zero_without_polling(self):
        with open(self.cfg["backup"]["local_lock_path"], "a+", encoding="utf-8") as holder:
            backup_job.fcntl.flock(holder.fileno(), backup_job.fcntl.LOCK_EX)
            with (
                mock.patch.object(backup_job, "acquire_local_lock", self.real_acquire_lock),
                mock.patch.object(backup_job, "poll_portal") as poll_portal,
            ):
                self.assertEqual(self.run_main("--poll"), 0)
        poll_portal.assert_not_called()


class PollTests(AgentTestCase):
    def test_action_none_returns_zero_and_starts_nothing(self):
        with mock.patch.object(backup_job, "execute_backup") as execute_backup:
            self.assertEqual(self.run_main("--poll"), 0)
        execute_backup.assert_not_called()
        self.assertEqual(self.portal.timeline(), ["poll"])
        self.assertEqual(self.portal.bodies(POLL_URL)[0]["hostname"], "source.test")

    def test_an_unreachable_portal_exits_two_without_a_failure_report(self):
        with mock.patch.object(backup_job.urllib.request, "urlopen", side_effect=OSError("refused")):
            self.assertEqual(self.run_main("--poll"), 2)
        self.send_mail.assert_not_called()

    def test_a_backup_command_runs_and_posts_running_then_success(self):
        self.portal.poll_answer = backup_command()
        self.assertEqual(self.run_main("--poll"), 0)

        self.assertEqual(
            self.portal.timeline(),
            ["poll", "command:running", "status:started", "status:success", "command:success", "log:success"],
        )
        run_id = self.portal.commands()[-1]["run_id"]
        self.assertEqual(len(run_id), 17)
        self.assertTrue(run_id.isdigit())
        self.assertEqual(self.portal.bodies(LOG_URL)[0]["run_id"], run_id)
        self.assertIn("BACKUP OK", self.portal.bodies(LOG_URL)[0]["log_text"])
        self.assertEqual(self.portal.bodies(LOG_URL)[0]["command_id"], 7)

        marker = json.loads(self.host.written[f"{REMOTE_HOME}/{run_id}/.backup-ok"])
        self.assertEqual((marker["status"], marker["run_id"]), ("ok", run_id))
        self.assertEqual(marker["command_id"], 7)
        self.assertEqual(marker["content_hashes"], {"filesystem/data.tar.zst": DIGEST})
        self.assertIsNotNone(marker["run_content_sha256"])
        self.assertEqual(self.host.write_order, ["manifest.json", ".backup-ok"])

        self.assertEqual(json.loads(self.state_path.read_text(encoding="utf-8"))["last_run_id"], run_id)
        self.send_mail.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "policy paths are POSIX paths")
    def test_a_command_policy_replaces_the_configured_sources(self):
        other = self.root / "policy-source"
        other.mkdir()
        self.portal.poll_answer = backup_command(
            policy={
                "id": 3, "name": "Web",
                "paths": [{"source_path": str(other), "target_name": "web", "mode": "tar"}],
            }
        )
        self.assertEqual(self.run_main("--poll"), 0)
        self.assertIn("Policy Web", self.portal.commands()[0]["message"])
        marker = json.loads(self.host.written[self.host.markers()[0]])
        self.assertEqual(marker["policy"]["id"], 3)
        self.assertEqual(list(marker["filesystem"]["sources"]), [str(other)])
        self.assertIn("filesystem/web.tar.zst", marker["content_hashes"])

    def test_not_due_without_force_posts_skipped(self):
        self.remember_recent_success()
        self.portal.poll_answer = backup_command()
        with mock.patch.object(backup_job, "execute_backup") as execute_backup:
            self.assertEqual(self.run_main("--poll"), 0)
        execute_backup.assert_not_called()
        self.assertEqual(self.portal.timeline(), ["poll", "command:skipped"])
        self.assertIn("Intervall nicht abgelaufen", self.portal.commands()[0]["message"])

    def test_force_runs_a_command_that_is_not_due(self):
        report = {"run_id": "1", "logical_run_bytes": 0}
        for label, flags, command in (
            ("agent flag", ["--force"], backup_command()),
            ("portal order", [], backup_command(force=True)),
        ):
            with self.subTest(label):
                self.remember_recent_success()
                self.portal.poll_answer = command
                with mock.patch.object(backup_job, "execute_backup", return_value=report) as execute_backup:
                    self.assertEqual(self.run_main("--poll", *flags), 0)
                execute_backup.assert_called_once()

    def test_an_exception_reports_failure_everywhere_and_uploads_the_log(self):
        self.assertEqual(self.failing_run(), 2)

        self.assertEqual(
            self.portal.timeline(),
            ["poll", "command:running", "status:started", "command:failure", "status:failure", "log:failure"],
        )
        run_id = self.portal.bodies(STATUS_URL)[0]["payload"]["run_id"]
        command = self.portal.commands()[-1]
        self.assertEqual(command["run_id"], run_id)
        self.assertIn("RuntimeError", command["message"])
        event = self.portal.bodies(STATUS_URL)[-1]["payload"]
        self.assertEqual((event["run_id"], event["command_id"]), (run_id, 7))
        self.assertEqual((event["phase"], event["error_type"]), ("filesystem", "RuntimeError"))
        log = self.portal.bodies(LOG_URL)[0]
        self.assertEqual((log["run_id"], log["phase"]), (run_id, "filesystem"))
        self.assertEqual(log["report"]["status"], "failure")
        self.assertIn("BACKUP FEHLGESCHLAGEN", log["log_text"])
        self.assertEqual(self.host.markers(), [])
        self.assertFalse(self.state_path.exists())


class FailureMailTests(AgentTestCase):
    def test_mail_on_failure_sends_the_mail(self):
        self.assertEqual(self.failing_run(), 2)
        self.send_mail.assert_called_once()
        self.assertIn("[Backup-FEHLER]", self.send_mail.call_args.args[1])
        self.assertIs(self.send_mail.call_args.kwargs["success"], False)
        self.assertIn(("Phase", "filesystem"), self.send_mail.call_args.kwargs["report_rows"])

    def test_without_mail_on_failure_nothing_is_sent(self):
        self.cfg["notifications"]["mail_on_failure"] = False
        self.assertEqual(self.failing_run(), 2)
        self.send_mail.assert_not_called()
        self.assertIn("status:failure", self.portal.timeline())

    def test_a_failing_send_mail_does_not_change_the_exit_path(self):
        self.send_mail.side_effect = smtplib.SMTPException("mail server down")
        self.assertEqual(self.failing_run(), 2)
        self.send_mail.assert_called_once()
        self.assertEqual(
            self.portal.timeline()[-3:], ["command:failure", "status:failure", "log:failure"]
        )


class MissingSourceTests(AgentTestCase):
    def assert_failed_without_marker(self, expected_phase):
        self.portal.poll_answer = backup_command()
        self.assertEqual(self.run_main("--poll"), 2)
        self.assertEqual(self.host.markers(), [])
        self.assertNotIn("status:success", self.portal.timeline())
        self.assertEqual(self.portal.commands()[-1]["status"], "failure")
        self.assertEqual(self.portal.bodies(STATUS_URL)[-1]["payload"]["phase"], expected_phase)
        self.assertFalse(self.state_path.exists())

    def test_a_missing_source_fails_the_run_in_preflight(self):
        self.cfg["backup"]["sources"] = [str(self.root / "gone")]
        self.assert_failed_without_marker("preflight")

    def test_a_source_that_vanishes_after_preflight_fails_the_run(self):
        self.cfg["backup"]["sources"] = [str(self.root / "gone")]
        self.host.du_finds_everything = True
        self.assert_failed_without_marker("filesystem")
        self.assertIn("Backupquelle fehlt", self.portal.commands()[-1]["message"])

    def test_one_missing_source_of_several_fails_the_whole_run(self):
        self.cfg["backup"]["sources"] = [str(self.source), str(self.root / "gone")]
        self.host.du_finds_everything = True
        self.assert_failed_without_marker("filesystem")


class StreamCompressedTests(AgentTestCase):
    REMOTE_FILE = f"{REMOTE_HOME}/20260101000000000/filesystem/data.tar.zst"

    def stream(self, attempts=1):
        backup_job.stream_compressed(self.cfg, ["tar", "-cf", "-", "data"], self.REMOTE_FILE, attempts=attempts)

    def removals(self):
        return [command for command in self.host.remote_commands if command.startswith("rm -f")]

    def test_a_failure_removes_the_remote_partial(self):
        self.host.pipeline_results.append(finished(returncode=1, stderr="zstd: write error\n"))
        with self.assertLogs("raven-backup", level="WARNING"), self.assertRaisesRegex(
            RuntimeError, "Status 1: zstd: write error"
        ):
            self.stream()
        self.assertEqual(len(self.removals()), 1)
        self.assertEqual(shlex.split(self.removals()[0])[3:], [self.REMOTE_FILE + ".partial", self.REMOTE_FILE])
        self.assertEqual(backup_job.RUN_CONTENT_HASHES, {})

    def test_every_failed_attempt_cleans_up_before_the_retry(self):
        self.host.pipeline_results.append(finished(returncode=1))
        with self.assertLogs("raven-backup", level="WARNING"):
            self.stream(attempts=2)
        self.assertEqual(len(self.host.pipelines), 2)
        self.assertEqual(len(self.removals()), 1)
        self.assertEqual(backup_job.RUN_CONTENT_HASHES, {self.REMOTE_FILE: DIGEST})

    def test_a_failing_cleanup_keeps_the_pipeline_error(self):
        # The rm runs through the same SSH link that
        # usually just failed, and its RuntimeError replaces the stream error,
        # so the run reports a failed rm instead of the status and diagnostics.
        self.host.failing_prefixes.append("rm -f")
        self.host.pipeline_results.append(finished(returncode=255, stderr="ssh: connection lost\n"))
        with self.assertLogs("raven-backup", level="WARNING"), self.assertRaisesRegex(
            RuntimeError, "ssh: connection lost"
        ):
            self.stream()

    def test_the_checksum_of_a_success_is_recorded(self):
        self.stream()
        self.assertEqual(backup_job.RUN_CONTENT_HASHES, {self.REMOTE_FILE: DIGEST})
        self.assertEqual(self.removals(), [])

    def test_the_file_is_hashed_as_partial_before_it_is_published(self):
        self.stream()
        pipeline = self.host.pipelines[0]
        self.assertLess(pipeline.index("sha256sum"), pipeline.index("mv -f"))
        self.assertIn(".partial", pipeline[pipeline.index("sha256sum"):])

    def test_a_missing_checksum_only_warns(self):
        for label, stdout in (("empty", ""), ("garbage", "not-a-digest  file.partial\n")):
            with self.subTest(label):
                self.host.pipeline_results.append(finished(stdout=stdout))
                with self.assertLogs("raven-backup", level="WARNING") as logs:
                    self.stream()
                self.assertIn("Keine Pruefsumme", logs.output[0])
                self.assertEqual(backup_job.RUN_CONTENT_HASHES, {})
                self.assertEqual(self.removals(), [])

    def test_a_run_without_checksums_still_finishes_without_a_fingerprint(self):
        self.host.pipeline_results.append(finished(stdout=""))
        self.portal.poll_answer = backup_command()
        self.assertEqual(self.run_main("--poll"), 0)
        marker = json.loads(self.host.written[self.host.markers()[0]])
        self.assertEqual(marker["content_hashes"], {})
        self.assertIsNone(marker["run_content_sha256"])


class ScriptUpdateTests(AgentTestCase):
    ORIGINAL = b"#!/usr/bin/env python3\nprint('old')\n"

    def setUp(self):
        super().setUp()
        self.script = self.root / "backup_job.py"
        self.script.write_bytes(self.ORIGINAL)
        self.start(mock.patch.object(backup_job, "script_path", return_value=self.script))

    @staticmethod
    def update_for(content, digest=None):
        return {
            "sha256": digest or hashlib.sha256(content).hexdigest(),
            "content_b64": base64.b64encode(content).decode("ascii"),
        }

    def test_a_digest_mismatch_is_rejected(self):
        update = self.update_for(b"#!/bin/sh\necho new\n", digest="0" * 64)
        with self.assertRaisesRegex(RuntimeError, "Pruefsumme"):
            backup_job.apply_script_update(update)
        self.assertEqual(self.script.read_bytes(), self.ORIGINAL)

    def test_a_script_without_shebang_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "Interpreter-Header"):
            backup_job.apply_script_update(self.update_for(b"print('new')\n"))
        self.assertEqual(self.script.read_bytes(), self.ORIGINAL)

    def test_invalid_base64_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "ungueltiges Agent-Skript"):
            backup_job.apply_script_update({"sha256": "0" * 64, "content_b64": "%%%"})
        self.assertEqual(self.script.read_bytes(), self.ORIGINAL)

    def test_a_valid_update_replaces_the_script(self):
        content = b"#!/usr/bin/env python3\nprint('new')\n"
        backup_job.apply_script_update(self.update_for(content))
        self.assertEqual(self.script.read_bytes(), content)
        self.assertEqual(list(self.root.glob(".backup_job.py.*")), [])

    @unittest.skipUnless(os.name == "posix", "file modes need POSIX")
    def test_a_valid_update_stays_private_and_executable(self):
        backup_job.apply_script_update(self.update_for(b"#!/bin/sh\necho new\n"))
        self.assertEqual(stat.S_IMODE(self.script.stat().st_mode), 0o700)

    def test_a_rejected_update_does_not_stop_the_poll(self):
        self.portal.poll_answer = {
            "action": "none", "script_update": self.update_for(b"no shebang\n"),
        }
        self.assertEqual(self.run_main("--poll"), 0)
        self.assertEqual(self.script.read_bytes(), self.ORIGINAL)


if __name__ == "__main__":
    unittest.main()
