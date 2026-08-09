import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))

import backup_schedule as schedule  # noqa: E402


TZ = timezone(timedelta(hours=2))


def at(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 8, day, hour, minute, tzinfo=TZ)


class IntervalValidationTests(unittest.TestCase):
    def test_accepts_divisors_and_multiples_of_a_day(self):
        for hours in schedule.INTERVAL_CHOICES:
            self.assertEqual(schedule.normalized_interval_hours(hours), hours)

    def test_rejects_patterns_that_would_drift(self):
        for hours in (5, 7, 36, 100):
            with self.assertRaises(ValueError):
                schedule.normalized_interval_hours(hours)

    def test_rejects_out_of_range(self):
        for hours in (0, -24, 192):
            with self.assertRaises(ValueError):
                schedule.normalized_interval_hours(hours)


class ScheduleWindowTests(unittest.TestCase):
    def test_daily_slot_before_the_desired_time_belongs_to_yesterday(self):
        current, following = schedule.schedule_window(at(12, 1, 30), 2, 0, 24)
        self.assertEqual(current, at(11, 2))
        self.assertEqual(following, at(12, 2))

    def test_daily_slot_after_the_desired_time_is_today(self):
        current, following = schedule.schedule_window(at(12, 2, 0), 2, 0, 24)
        self.assertEqual(current, at(12, 2))
        self.assertEqual(following, at(13, 2))

    def test_six_hour_interval_steps_across_midnight(self):
        current, following = schedule.schedule_window(at(12, 0, 30), 2, 0, 6)
        self.assertEqual(current, at(11, 20))
        self.assertEqual(following, at(12, 2))

    def test_six_hour_interval_inside_the_day(self):
        current, following = schedule.schedule_window(at(12, 15, 0), 2, 0, 6)
        self.assertEqual(current, at(12, 14))
        self.assertEqual(following, at(12, 20))

    def test_multi_day_interval_keeps_a_stable_rhythm(self):
        first, following = schedule.schedule_window(at(12, 5, 0), 2, 0, 48)
        self.assertEqual(following - first, timedelta(days=2))
        # A later moment inside the same slot resolves to the same slot.
        again, _ = schedule.schedule_window(at(13, 23, 0), 2, 0, 48)
        self.assertEqual(again, first)
        # And the slot after it is exactly the announced follower.
        beyond, _ = schedule.schedule_window(following + timedelta(hours=1), 2, 0, 48)
        self.assertEqual(beyond, following)


class DueTests(unittest.TestCase):
    def test_without_any_backup_the_slot_is_due(self):
        due, current, _following = schedule.is_due(at(12, 3), None, 2, 0, 24)
        self.assertTrue(due)
        self.assertEqual(current, at(12, 2))

    def test_success_inside_the_slot_satisfies_it(self):
        due, _current, following = schedule.is_due(at(12, 9), at(12, 2, 30), 2, 0, 24)
        self.assertFalse(due)
        self.assertEqual(following, at(13, 2))

    def test_success_before_the_slot_leaves_it_due(self):
        due, _current, _following = schedule.is_due(at(12, 9), at(11, 2, 30), 2, 0, 24)
        self.assertTrue(due)

    def test_next_due_at_switches_to_the_following_slot(self):
        self.assertEqual(schedule.next_due_at(at(12, 9), at(12, 2, 30), 2, 0, 24), at(13, 2))
        self.assertEqual(schedule.next_due_at(at(12, 9), at(11, 2, 30), 2, 0, 24), at(12, 2))

    def test_state_is_json_serialisable(self):
        state = schedule.schedule_state(at(12, 9), at(12, 2, 30), 2, 0, 24)
        self.assertEqual(state["interval_hours"], 24)
        self.assertFalse(state["due"])
        self.assertEqual(state["next_due_at"], at(13, 2).isoformat())
        self.assertEqual(state["last_success_at"], at(12, 2, 30).isoformat())


class StartOffsetTests(unittest.TestCase):
    def test_offset_is_capped_to_a_quarter_of_the_interval(self):
        self.assertEqual(schedule.normalized_offset_minutes(120, 24), 120)
        self.assertEqual(schedule.normalized_offset_minutes(60, 1), 15)
        self.assertEqual(schedule.normalized_offset_minutes(0, 24), 0)

    def test_offset_rejects_impossible_values(self):
        with self.assertRaises(ValueError):
            schedule.normalized_offset_minutes(-1, 24)
        with self.assertRaises(ValueError):
            schedule.normalized_offset_minutes(121, 24)

    def test_jitter_is_stable_and_inside_the_range(self):
        slot = at(12, 2)
        for seed in ("web1", "web2", "db-01"):
            first = schedule.slot_jitter(seed, slot, 15)
            self.assertEqual(first, schedule.slot_jitter(seed, slot, 15))
            self.assertLessEqual(abs(first), 15)
        # Different servers land on different minutes for the same slot.
        spread = {schedule.slot_jitter(f"host{index}", slot, 15) for index in range(20)}
        self.assertGreater(len(spread), 5)

    def test_jitter_changes_between_slots(self):
        seeds = [schedule.slot_jitter("web1", at(day, 2), 30) for day in range(10, 20)]
        self.assertGreater(len(set(seeds)), 3)

    def test_window_opens_before_the_desired_time(self):
        plan = schedule.slot_plan(at(12, 3), 2, 0, 24, 15, "web1")
        self.assertEqual(plan["window_start"], at(12, 1, 45))
        self.assertLessEqual(abs((plan["planned_start"] - at(12, 2)).total_seconds()), 15 * 60)

    def test_an_early_run_satisfies_the_slot(self):
        # Forced at 01:50, ten minutes before the desired time, still counts.
        due, _window, _following = schedule.is_due(at(12, 6), at(12, 1, 50), 2, 0, 24, 15, "web1")
        self.assertFalse(due)

    def test_a_run_before_the_window_leaves_the_slot_due(self):
        due, _window, _following = schedule.is_due(at(12, 6), at(12, 1, 30), 2, 0, 24, 15, "web1")
        self.assertTrue(due)

    def test_checker_deadline_grows_with_the_offset(self):
        self.assertEqual(schedule.checker_max_age_hours(24, 0), 36.0)
        self.assertEqual(schedule.checker_max_age_hours(24, 30), 36.5)


class DescriptionTests(unittest.TestCase):
    def test_descriptions(self):
        self.assertEqual(schedule.describe(2, 0, 24), "täglich 02:00")
        self.assertEqual(schedule.describe(2, 30, 6), "alle 6 Stunden ab 02:30")
        self.assertEqual(schedule.describe(3, 0, 48), "alle 2 Tage 03:00")
        self.assertEqual(schedule.describe(3, 0, 168), "wöchentlich 03:00")
        self.assertEqual(schedule.describe(2, 0, 24, 15), "täglich 02:00 ± 15 min")

    def test_checker_age_matches_the_historical_default(self):
        self.assertEqual(schedule.checker_max_age_hours(24), 36.0)
        self.assertEqual(schedule.checker_max_age_hours(6), 9.0)


if __name__ == "__main__":
    unittest.main()
