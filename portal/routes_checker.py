"""The checker pages and the policy cleanup runs it executes."""

from __future__ import annotations

import sqlite3
from datetime import datetime

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from core import (
    CHECKER_CONFIG_PATH, CHECKER_SCRIPT, CHECKER_STATE, checker_cleanup_configuration, db,
    format_size, now_iso,
)
from auth import audit, require_user, verify_csrf
from rendering import checker_results, render
from workers import (
    CHECKER_WAKEUP, checker_next_time, enqueue_checker_run, enqueue_policy_cleanup_run,
)


router = APIRouter()


@router.post("/processes/cleanup/{policy_id}")
def policy_cleanup_trigger(
    request: Request,
    policy_id: int,
    mode: str = Form(...),
    confirmed: str | None = Form(None),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    if mode not in {"execute", "dry_run"}:
        raise HTTPException(400, "Ungültiger Cleanup-Modus")
    if mode == "execute" and confirmed != "yes":
        raise HTTPException(400, "Der löschende Cleanup-Lauf muss ausdrücklich bestätigt werden")
    run_id, result = enqueue_policy_cleanup_run(
        policy_id, int(user["id"]), dry_run=mode == "dry_run"
    )
    failures = {
        "not_found": (404, "Backup-Policy nicht gefunden"),
        "no_clients": (409, "Der Policy sind keine aktiven Server zugewiesen"),
        "maintenance_busy": (409, "Ein Checker- oder Cleanup-Lauf ist bereits aktiv"),
        "backup_active": (409, "Mindestens ein Backup dieser Policy ist gerade aktiv oder eingeplant"),
    }
    if run_id is None:
        status_code, message = failures.get(result, (409, "Cleanup konnte nicht eingeplant werden"))
        raise HTTPException(status_code, message)
    audit(
        request, "cleanup.trigger", str(policy_id),
        f"run_id={run_id}, mode={mode}", user_id=user["id"],
    )
    return RedirectResponse(f"/processes/cleanup/runs/{run_id}", status_code=303)


@router.get("/processes/cleanup/runs/{run_id}", response_class=HTMLResponse)
def policy_cleanup_run_detail(request: Request, run_id: int):
    require_user(request, admin=True)
    with db() as connection:
        run = connection.execute(
            "SELECT pr.*,u.username AS requested_by_name FROM policy_cleanup_runs pr "
            "LEFT JOIN users u ON u.id=pr.requested_by WHERE pr.id=?",
            (run_id,),
        ).fetchone()
    if not run:
        raise HTTPException(404, "Cleanup-Lauf nicht gefunden")
    result = dict(run)
    result["reclaimed_size"] = format_size(result.get("reclaimed_bytes"))
    return render(request, "cleanup_run.html", {"run": result})


@router.get("/checker", response_class=HTMLResponse)
def checker_page(request: Request):
    require_user(request)
    with db() as connection:
        settings = connection.execute("SELECT * FROM checker_settings WHERE id=1").fetchone()
        runs = connection.execute(
            "SELECT cr.*,u.username AS requested_by_name FROM checker_runs cr "
            "LEFT JOIN users u ON u.id=cr.requested_by ORDER BY cr.id DESC LIMIT 30"
        ).fetchall()
    state = checker_results()
    statuses = {"OK": 0, "STALE": 0, "ERROR": 0, "UNKNOWN": 0}
    for entry in state.values():
        status = str(entry.get("result", {}).get("status", "UNKNOWN")).upper()
        statuses[status if status in statuses else "UNKNOWN"] += 1
    return render(request, "checker.html", {
        "settings": dict(settings),
        "checker_mail_summary": checker_mail_summary(settings),
        "runs": runs,
        "statuses": statuses,
        "state_updated": datetime.fromtimestamp(CHECKER_STATE.stat().st_mtime).astimezone().isoformat(timespec="seconds")
        if CHECKER_STATE.is_file() else None,
        "script_path": str(CHECKER_SCRIPT),
        "config_path": str(CHECKER_CONFIG_PATH),
        "cleanup": checker_cleanup_configuration(),
    })


@router.post("/checker/settings")
def checker_settings_update(
    request: Request,
    interval_minutes: int = Form(...),
    reminder_hours: int = Form(24),
    enabled: str | None = Form(None),
    mail_on_problem: str | None = Form(None),
    mail_on_recovery: str | None = Form(None),
    mail_on_clean_run: str | None = Form(None),
    alarm_on_unchanged: str | None = Form(None),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    if not 5 <= interval_minutes <= 1440:
        raise HTTPException(400, "Checker-Intervall muss zwischen 5 und 1440 Minuten liegen")
    if not 1 <= reminder_hours <= 720:
        raise HTTPException(400, "Erinnerungsabstand muss zwischen 1 und 720 Stunden liegen")
    with db() as connection:
        connection.execute(
            "UPDATE checker_settings SET enabled=?,interval_minutes=?,next_run_at=?,mail_on_problem=?,"
            "mail_on_recovery=?,mail_on_clean_run=?,alarm_on_unchanged=?,reminder_hours=?,"
            "updated_by=?,updated_at=? WHERE id=1",
            (
                bool(enabled), interval_minutes, checker_next_time(interval_minutes),
                bool(mail_on_problem), bool(mail_on_recovery), bool(mail_on_clean_run),
                bool(alarm_on_unchanged), reminder_hours, user["id"], now_iso(),
            ),
        )
    CHECKER_WAKEUP.set()
    audit(
        request, "checker.settings", "portal-checker",
        f"enabled={bool(enabled)}, interval={interval_minutes}, problem={bool(mail_on_problem)}, "
        f"recovery={bool(mail_on_recovery)}, clean={bool(mail_on_clean_run)}, "
        f"unchanged_alarm={bool(alarm_on_unchanged)}, reminder={reminder_hours}",
        user_id=user["id"],
    )
    return RedirectResponse("/checker", status_code=303)


@router.post("/checker/run")
def checker_run_trigger(
    request: Request,
    mode: str = Form(...),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    labels = {
        "normal": "normal",
        "force": "force-report",
        "dry_run": "dry-run",
        "smtp_check": "smtp-check",
        "smtp_test": "smtp-test",
    }
    if mode not in labels:
        raise HTTPException(400, "Ungueltiger Checker-Modus")
    run_id = enqueue_checker_run(mode, user["id"])
    if run_id is None:
        raise HTTPException(409, "Ein Checker-Lauf ist bereits queued oder aktiv")
    audit(request, "checker.trigger", "portal-checker", f"run_id={run_id}, mode={labels[mode]}", user_id=user["id"])
    return RedirectResponse("/checker", status_code=303)


@router.get("/checker/runs/{run_id}", response_class=HTMLResponse)
def checker_run_detail(request: Request, run_id: int):
    require_user(request, admin=True)
    with db() as connection:
        run = connection.execute(
            "SELECT cr.*,u.username AS requested_by_name FROM checker_runs cr "
            "LEFT JOIN users u ON u.id=cr.requested_by WHERE cr.id=?",
            (run_id,),
        ).fetchone()
    if not run:
        raise HTTPException(404, "Checker-Lauf nicht gefunden")
    return render(request, "checker_run.html", {"run": dict(run)})


def checker_mail_summary(settings: sqlite3.Row) -> str:
    """Name the check results the checker sends mail for."""
    events = [
        label
        for column, label in (
            ("mail_on_problem", "Probleme"),
            ("mail_on_recovery", "Wiederherstellung"),
            ("mail_on_clean_run", "fehlerfreier Lauf"),
        )
        if settings[column]
    ]
    if not events:
        return "keine"
    return f"{', '.join(events)} · Erinnerung alle {int(settings['reminder_hours'])} h"
