"""Page rendering and the view helpers several route modules share."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

import backup_schedule

from core import BASE_DIR, CHECKER_STATE, format_size
from auth import session_user


templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.filters["size"] = lambda value: format_size(value) if value is not None else "–"

NAV_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("explorer", ("/explorer",)),
    ("policies", ("/policies",)),
    ("checker", ("/checker",)),
    ("mirrors", ("/mirrors",)),
    ("processes", ("/processes",)),
    ("settings", ("/settings/application",)),
    ("smtp", ("/settings/smtp",)),
    ("certificates", ("/certificates",)),
    ("users", ("/users",)),
    ("account", ("/account",)),
    ("manual", ("/manual",)),
    ("servers", ("/", "/clients")),
)


def nav_section(path: str) -> str:
    """Map a request path to the sidebar entry that should light up."""
    if path.startswith("/clients/") and "/explorer" in path:
        return "explorer"
    for key, prefixes in NAV_SECTIONS:
        for prefix in prefixes:
            if path == prefix or (prefix != "/" and path.startswith(prefix)):
                return key
    return ""


def render(request: Request, name: str, context: dict[str, Any], status_code: int = 200) -> HTMLResponse:
    user = session_user(request)
    merged = {
        "request": request,
        "user": user,
        "csrf": user["csrf_token"] if user else "",
        "nav_active": nav_section(request.url.path),
        **context,
    }
    return templates.TemplateResponse(name, merged, status_code=status_code)


def checker_results() -> dict[str, Any]:
    try:
        state = json.loads(CHECKER_STATE.read_text(encoding="utf-8"))
        return state.get("users", {})
    except Exception:
        return {}


def policy_mail_summary(policy: sqlite3.Row) -> str:
    """Name the backup events a policy sends mail for."""
    events = [
        label
        for column, label in (
            ("mail_on_success", "Erfolg"),
            ("mail_on_failure", "Fehler"),
            ("mail_on_skipped", "Ablehnung"),
        )
        if policy[column]
    ]
    return ", ".join(events) if events else "keine"


def validated_schedule(
    hour: Any, minute: Any, interval_hours: Any, offset_minutes: Any = 0
) -> tuple[int, int, int, int]:
    try:
        hours = backup_schedule.normalized_interval_hours(interval_hours)
        return (
            backup_schedule.normalized_hour(hour),
            backup_schedule.normalized_minute(minute),
            hours,
            backup_schedule.normalized_offset_minutes(offset_minutes, hours),
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, str(exc) or "Ungueltiger Zeitplan") from exc
