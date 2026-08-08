#!/usr/bin/env python3
"""Backup schedule math shared by the portal scheduler, the agent API and the UI.

A schedule consists of a desired wall-clock time (hour and minute) and an
interval in hours. The desired time is the anchor of the pattern: with an
interval of 24 hours a backup is due once per day at that time, with an
interval of 6 hours it is due at the anchor and every six hours after it.

Only intervals that keep the anchor stable are allowed: either a divisor of 24
(sub-daily patterns that repeat cleanly across midnight) or a multiple of 24
(whole-day patterns that step from a fixed reference date).
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta
from typing import Any


INTERVAL_CHOICES = (1, 2, 3, 4, 6, 8, 12, 24, 48, 72, 96, 120, 168)
DEFAULT_INTERVAL_HOURS = 24
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 168

# Fixed reference date for intervals of whole days so multi-day patterns stay on
# the same days regardless of when the policy was created or edited.
SLOT_EPOCH = date(2000, 1, 3)

# The checker must not alarm before the next backup is even due. Historically the
# default was 36 hours for a daily schedule, which is exactly this factor.
CHECKER_AGE_FACTOR = 1.5


def normalized_hour(value: Any) -> int:
    hour = int(value)
    if not 0 <= hour <= 23:
        raise ValueError("Stunde muss zwischen 0 und 23 liegen")
    return hour


def normalized_minute(value: Any) -> int:
    minute = int(value)
    if not 0 <= minute <= 59:
        raise ValueError("Minute muss zwischen 0 und 59 liegen")
    return minute


def normalized_interval_hours(value: Any) -> int:
    hours = int(value)
    if not MIN_INTERVAL_HOURS <= hours <= MAX_INTERVAL_HOURS:
        raise ValueError(
            f"Intervall muss zwischen {MIN_INTERVAL_HOURS} und {MAX_INTERVAL_HOURS} Stunden liegen"
        )
    if 24 % hours and hours % 24:
        raise ValueError("Intervall muss ein Teiler von 24 Stunden oder ein Vielfaches von 24 Stunden sein")
    return hours


def _slot_at(day: date, hour: int, minute: int, tzinfo: Any) -> datetime:
    return datetime.combine(day, time(hour, minute), tzinfo)


def schedule_window(now: datetime, hour: int, minute: int, interval_hours: int) -> tuple[datetime, datetime]:
    """Return the slot that is currently open and the slot that follows it.

    The current slot is the most recent scheduled time at or before ``now``.
    """
    hour = normalized_hour(hour)
    minute = normalized_minute(minute)
    interval_hours = normalized_interval_hours(interval_hours)
    tzinfo = now.tzinfo
    if interval_hours % 24 == 0:
        step = timedelta(days=interval_hours // 24)
        offset = (now.date() - SLOT_EPOCH).days % step.days
        current = _slot_at(now.date() - timedelta(days=offset), hour, minute, tzinfo)
        if current > now:
            current = _slot_at(current.date() - step, hour, minute, tzinfo)
        return current, _slot_at(current.date() + step, hour, minute, tzinfo)
    step = timedelta(hours=interval_hours)
    current = _slot_at(now.date(), hour, minute, tzinfo)
    while current > now:
        current -= step
    while current + step <= now:
        current += step
    return current, current + step


def is_due(
    now: datetime,
    last_success: datetime | None,
    hour: int,
    minute: int,
    interval_hours: int,
) -> tuple[bool, datetime, datetime]:
    """Return whether a backup is due plus the current and the following slot."""
    current, following = schedule_window(now, hour, minute, interval_hours)
    due = last_success is None or last_success < current
    return due, current, following


def next_due_at(
    now: datetime,
    last_success: datetime | None,
    hour: int,
    minute: int,
    interval_hours: int,
) -> datetime:
    """Return the point in time at which the next backup may start."""
    due, current, following = is_due(now, last_success, hour, minute, interval_hours)
    return current if due else following


def schedule_state(
    now: datetime,
    last_success: datetime | None,
    hour: int,
    minute: int,
    interval_hours: int,
) -> dict[str, Any]:
    """Return a JSON-serialisable view of the schedule for agents and templates."""
    due, current, following = is_due(now, last_success, hour, minute, interval_hours)
    return {
        "hour": normalized_hour(hour),
        "minute": normalized_minute(minute),
        "interval_hours": normalized_interval_hours(interval_hours),
        "current_slot": current.isoformat(),
        "next_slot": following.isoformat(),
        "next_due_at": (current if due else following).isoformat(),
        "last_success_at": last_success.isoformat() if last_success else None,
        "due": due,
    }


def describe(hour: int, minute: int, interval_hours: int) -> str:
    """Return a short German description such as 'täglich 02:00'."""
    hour = normalized_hour(hour)
    minute = normalized_minute(minute)
    interval_hours = normalized_interval_hours(interval_hours)
    clock = f"{hour:02d}:{minute:02d}"
    if interval_hours == 24:
        return f"täglich {clock}"
    if interval_hours < 24:
        return f"alle {interval_hours} Stunden ab {clock}"
    days = interval_hours // 24
    if days == 7:
        return f"wöchentlich {clock}"
    return f"alle {days} Tage {clock}"


def checker_max_age_hours(interval_hours: int) -> float:
    """Return the backup age after which the checker should raise an alarm."""
    return round(normalized_interval_hours(interval_hours) * CHECKER_AGE_FACTOR, 2)
