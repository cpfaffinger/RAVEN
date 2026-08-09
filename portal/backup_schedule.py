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

import hashlib
from datetime import date, datetime, time, timedelta
from typing import Any


INTERVAL_CHOICES = (1, 2, 3, 4, 6, 8, 12, 24, 48, 72, 96, 120, 168)
DEFAULT_INTERVAL_HOURS = 24
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 168
MAX_OFFSET_MINUTES = 120

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


def normalized_offset_minutes(value: Any, interval_hours: int) -> int:
    """Clamp the random start offset so neighbouring slots cannot overlap."""
    offset = int(value or 0)
    if offset < 0:
        raise ValueError("Startversatz darf nicht negativ sein")
    if offset > MAX_OFFSET_MINUTES:
        raise ValueError(f"Startversatz darf hoechstens {MAX_OFFSET_MINUTES} Minuten betragen")
    return min(offset, normalized_interval_hours(interval_hours) * 60 // 4)


def slot_jitter(seed: str, slot: datetime, offset_minutes: int) -> int:
    """Return a stable pseudo-random shift in [-offset, +offset] for one slot.

    The value only depends on the seed and the slot, so every scheduler pass
    agrees on the same start time instead of moving the target continuously.
    """
    if offset_minutes <= 0:
        return 0
    digest = hashlib.blake2b(f"{seed}|{slot.isoformat()}".encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % (offset_minutes * 2 + 1) - offset_minutes


def slot_plan(
    now: datetime,
    hour: int,
    minute: int,
    interval_hours: int,
    offset_minutes: int = 0,
    seed: str = "",
) -> dict[str, Any]:
    """Return the current slot with its acceptance window and planned start."""
    current, following = schedule_window(now, hour, minute, interval_hours)
    offset = normalized_offset_minutes(offset_minutes, interval_hours)
    span = timedelta(minutes=offset)
    return {
        "slot": current,
        "next_slot": following,
        "offset_minutes": offset,
        # A backup started anywhere inside the window counts for this slot, so an
        # early forced run is not repeated once the planned start arrives.
        "window_start": current - span,
        "next_window_start": following - span,
        "planned_start": current + timedelta(minutes=slot_jitter(seed, current, offset)),
        "next_planned_start": following + timedelta(minutes=slot_jitter(seed, following, offset)),
    }


def is_due(
    now: datetime,
    last_success: datetime | None,
    hour: int,
    minute: int,
    interval_hours: int,
    offset_minutes: int = 0,
    seed: str = "",
) -> tuple[bool, datetime, datetime]:
    """Return whether the interval elapsed plus the current and the next window."""
    plan = slot_plan(now, hour, minute, interval_hours, offset_minutes, seed)
    due = last_success is None or last_success < plan["window_start"]
    return due, plan["window_start"], plan["next_window_start"]


def next_due_at(
    now: datetime,
    last_success: datetime | None,
    hour: int,
    minute: int,
    interval_hours: int,
    offset_minutes: int = 0,
    seed: str = "",
) -> datetime:
    """Return the point in time at which the next backup may start."""
    plan = slot_plan(now, hour, minute, interval_hours, offset_minutes, seed)
    due = last_success is None or last_success < plan["window_start"]
    return plan["planned_start"] if due else plan["next_planned_start"]


def schedule_state(
    now: datetime,
    last_success: datetime | None,
    hour: int,
    minute: int,
    interval_hours: int,
    offset_minutes: int = 0,
    seed: str = "",
) -> dict[str, Any]:
    """Return a JSON-serialisable view of the schedule for agents and templates."""
    plan = slot_plan(now, hour, minute, interval_hours, offset_minutes, seed)
    due = last_success is None or last_success < plan["window_start"]
    return {
        "hour": normalized_hour(hour),
        "minute": normalized_minute(minute),
        "interval_hours": normalized_interval_hours(interval_hours),
        "offset_minutes": plan["offset_minutes"],
        "current_slot": plan["window_start"].isoformat(),
        "next_slot": plan["next_window_start"].isoformat(),
        "planned_start": plan["planned_start"].isoformat(),
        "next_due_at": (plan["planned_start"] if due else plan["next_planned_start"]).isoformat(),
        "last_success_at": last_success.isoformat() if last_success else None,
        "due": due,
        "ready": due and now >= plan["planned_start"],
    }


def describe(hour: int, minute: int, interval_hours: int, offset_minutes: int = 0) -> str:
    """Return a short German description such as 'täglich 02:00 ± 15 min'."""
    hour = normalized_hour(hour)
    minute = normalized_minute(minute)
    interval_hours = normalized_interval_hours(interval_hours)
    offset = normalized_offset_minutes(offset_minutes, interval_hours)
    clock = f"{hour:02d}:{minute:02d}"
    if offset:
        clock += f" ± {offset} min"
    if interval_hours == 24:
        return f"täglich {clock}"
    if interval_hours < 24:
        return f"alle {interval_hours} Stunden ab {clock}"
    days = interval_hours // 24
    if days == 7:
        return f"wöchentlich {clock}"
    return f"alle {days} Tage {clock}"


def checker_max_age_hours(interval_hours: int, offset_minutes: int = 0) -> float:
    """Return the backup age after which the checker should raise an alarm."""
    hours = normalized_interval_hours(interval_hours)
    offset = normalized_offset_minutes(offset_minutes, hours)
    return round(hours * CHECKER_AGE_FACTOR + offset / 60, 2)
