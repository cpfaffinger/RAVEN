import os
import shutil
import subprocess
import sys
import time
import types
import unittest
from pathlib import Path


try:
    import fcntl  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - Windows test runner compatibility
    sys.modules["fcntl"] = types.ModuleType("fcntl")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backupscript"))

import backup_job  # noqa: E402


BASH = shutil.which("bash")


@unittest.skipUnless(BASH, "bash is required to run the producer shell code")
class ProducerShellTests(unittest.TestCase):
    def run_pipeline(self, producer: list[str], tolerated: frozenset[int]) -> subprocess.CompletedProcess:
        shell = backup_job.producer_shell(producer, tolerated) + " | cat"
        return subprocess.run(
            [BASH, "-o", "pipefail", "-c", shell], capture_output=True, text=True, check=False
        )

    def test_without_tolerated_codes_the_command_is_unchanged(self):
        self.assertEqual(backup_job.producer_shell(["tar", "-cf", "-", "etc"], frozenset()), "tar -cf - etc")

    def test_tar_warning_exit_passes_the_pipeline(self):
        proc = self.run_pipeline(["sh", "-c", "echo archive; exit 1"], frozenset({1}))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "archive\n")
        self.assertIn("producer exit 1 toleriert", proc.stderr)

    def test_real_errors_still_fail_the_pipeline(self):
        proc = self.run_pipeline(["sh", "-c", "exit 2"], frozenset({1}))
        self.assertEqual(proc.returncode, 2)

    def test_untolerated_exit_one_fails_the_pipeline(self):
        proc = self.run_pipeline(["sh", "-c", "exit 1"], frozenset())
        self.assertEqual(proc.returncode, 1)

    def test_arguments_stay_quoted(self):
        proc = self.run_pipeline(["printf", "%s|", "a b", "c;d"], frozenset({1}))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "a b|c;d|")


@unittest.skipUnless(Path("/usr/bin/bash").exists() and hasattr(os, "killpg"), "a POSIX bash is required")
class RunPipelineTests(unittest.TestCase):
    def test_output_and_status_are_passed_through(self):
        proc = backup_job.run_pipeline("echo out; echo err >&2; exit 3")
        self.assertEqual((proc.returncode, proc.stdout.strip(), proc.stderr.strip()), (3, "out", "err"))

    def test_a_stalled_pipeline_dies_with_all_its_stages(self):
        started = time.monotonic()
        proc = backup_job.run_pipeline("sleep 30 | sleep 30", timeout=1)
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(proc.returncode, 124)
        self.assertIn("Zeitlimit", proc.stderr)


if __name__ == "__main__":
    unittest.main()
