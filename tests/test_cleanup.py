import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


try:
    import pwd  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - Windows test runner compatibility
    sys.modules["pwd"] = types.ModuleType("pwd")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import backup_check  # noqa: E402


class PolicyCleanupTests(unittest.TestCase):
    @staticmethod
    def completed_snapshot(home: Path, run_id: str) -> Path:
        snapshot = home / run_id
        snapshot.mkdir()
        marker = snapshot / ".backup-ok"
        marker.write_text(json.dumps({"status": "ok", "run_id": run_id}), encoding="utf-8")
        os.utime(marker, (1, 1))
        return snapshot

    def test_policy_retention_overrides_global_cleanup_and_keeps_current(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            enabled = root / "backup_enabled"
            disabled = root / "backup_disabled"
            enabled.mkdir()
            disabled.mkdir()
            for run_id in ("20260101000000000", "20260102000000000", "20260103000000000"):
                self.completed_snapshot(enabled, run_id)
            for run_id in ("20260101000000000", "20260102000000000"):
                self.completed_snapshot(disabled, run_id)
            current = enabled / "current"
            current.mkdir()

            config = {
                "monitor": {
                    "home_root": str(root),
                    "user_glob": "backup_*",
                    "ok_marker_name": ".backup-ok",
                    "volume_timeout_seconds": 1,
                },
                "cleanup": {
                    "enabled": False,
                    "snapshot_name_digits": 17,
                    "snapshot_retention_days": 30,
                    "minimum_snapshots_to_keep": 2,
                    "incomplete_snapshot_retention_hours": 48,
                    "legacy_file_retention_days": 5,
                    "policy_by_user": {
                        "backup_enabled": {
                            "enabled": True,
                            "retention_days": 1,
                            "minimum_snapshots_to_keep": 2,
                        },
                        "backup_disabled": {
                            "enabled": False,
                            "retention_days": 1,
                            "minimum_snapshots_to_keep": 1,
                        },
                    },
                },
            }

            with mock.patch.object(backup_check, "measure_volume_bytes", return_value=4096):
                result = backup_check.cleanup_backups(config, dry_run=True)

            self.assertIsNotNone(result)
            self.assertEqual(result.status, "OK")
            self.assertIn("1 erfolgreiche Snapshots", result.detail)
            self.assertEqual(result.volume_bytes, 4096)
            self.assertTrue(current.is_dir())

    def test_invalid_policy_mapping_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "policy_by_user"):
            backup_check.cleanup_backups(
                {"monitor": {}, "cleanup": {"enabled": True, "policy_by_user": []}},
                dry_run=True,
            )

    def test_manual_cleanup_ignores_hour_but_stays_inside_policy_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = root / "backup_selected"
            other = root / "backup_other"
            selected.mkdir()
            other.mkdir()
            selected_old = self.completed_snapshot(selected, "20260101000000000")
            self.completed_snapshot(selected, "20260102000000000")
            other_old = self.completed_snapshot(other, "20260101000000000")
            self.completed_snapshot(other, "20260102000000000")
            config = {
                "monitor": {
                    "home_root": str(root), "user_glob": "backup_*",
                    "ok_marker_name": ".backup-ok", "volume_timeout_seconds": 1,
                },
                "cleanup": {
                    "enabled": True, "run_hour": 23, "snapshot_name_digits": 17,
                    "snapshot_retention_days": 1, "minimum_snapshots_to_keep": 1,
                    "incomplete_snapshot_retention_hours": 48,
                    "legacy_file_retention_days": 5,
                    "policy_by_user": {
                        "backup_selected": {
                            "enabled": True, "retention_days": 1,
                            "minimum_snapshots_to_keep": 1,
                        }
                    },
                },
            }
            fixed_now = datetime(2026, 8, 14, 12, tzinfo=timezone.utc)
            with (
                mock.patch.object(backup_check, "local_now", return_value=fixed_now),
                mock.patch.object(backup_check, "measure_volume_bytes", return_value=2048),
            ):
                self.assertIsNone(backup_check.cleanup_backups(config, dry_run=False))
                result = backup_check.cleanup_backups(
                    config, dry_run=False, ignore_run_hour=True, policy_scope_only=True
                )

            self.assertEqual(result.status, "OK")
            self.assertFalse(selected_old.exists())
            self.assertTrue(other_old.exists())


if __name__ == "__main__":
    unittest.main()
