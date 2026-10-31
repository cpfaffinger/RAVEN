import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import backup_check  # noqa: E402


NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


def mirror(**overrides):
    state = {
        "name": "box1", "interval_hours": 216, "last_status": "success", "last_message": "",
        "last_run_at": NOW.isoformat(), "last_success_at": (NOW - timedelta(hours=10)).isoformat(),
    }
    state.update(overrides)
    return state


class MirrorResultTests(unittest.TestCase):
    def judge(self, **overrides):
        return backup_check.mirror_results([mirror(**overrides)], NOW)[0]

    def test_a_recent_success_is_fine(self):
        result = self.judge()
        self.assertEqual(result.status, "OK")
        self.assertEqual(result.user, "MIRROR_box1")
        self.assertAlmostEqual(result.age_hours, 10)

    def test_a_failed_run_alarms_with_its_message(self):
        result = self.judge(last_status="failure", last_message="rsync endete mit Status 10")
        self.assertEqual(result.status, "ERROR")
        self.assertIn("rsync endete mit Status 10", result.detail)

    def test_an_interrupted_run_alarms(self):
        self.assertEqual(self.judge(last_status="interrupted").status, "ERROR")

    def test_a_stale_success_alarms_after_two_intervals_and_a_day(self):
        limit = 2 * 216 + 24
        fresh = (NOW - timedelta(hours=limit - 1)).isoformat()
        stale = (NOW - timedelta(hours=limit + 1)).isoformat()
        self.assertEqual(self.judge(last_success_at=fresh).status, "OK")
        self.assertEqual(self.judge(last_success_at=stale).status, "ERROR")

    def test_a_new_mirror_without_any_run_stays_quiet(self):
        result = self.judge(last_status=None, last_success_at=None)
        self.assertEqual(result.status, "OK")
        self.assertIsNone(result.age_hours)


if __name__ == "__main__":
    unittest.main()
