"""Backup policies and their paths."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

import backup_schedule

from core import POLICY_TARGET_RE, application_settings, checker_cleanup_configuration, db, now_iso
from auth import audit, require_user, verify_csrf
from rendering import policy_mail_summary, render, validated_schedule


router = APIRouter()


def validated_retention(
    cleanup_enabled: str | None, retention_days: Any, minimum_snapshots_to_keep: Any
) -> tuple[bool, int, int]:
    try:
        days = int(retention_days)
        minimum = int(minimum_snapshots_to_keep)
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, "Ungültige Aufbewahrung") from exc
    if not 1 <= days <= 3650:
        raise HTTPException(400, "Aufbewahrung muss zwischen 1 und 3650 Tagen liegen")
    if not 1 <= minimum <= 100:
        raise HTTPException(400, "Mindestens zu behaltende Backups müssen zwischen 1 und 100 liegen")
    return bool(cleanup_enabled), days, minimum


def validated_policy_path(source_path: str, target_name: str, mode: str) -> tuple[str, str, str]:
    source_path = source_path.strip().rstrip("/") or "/"
    target_name = target_name.strip().lower()
    path = Path(source_path)
    if not path.is_absolute() or source_path == "/" or ".." in path.parts or any(ord(char) < 32 for char in source_path):
        raise HTTPException(400, "Quellpfad muss ein sicherer absoluter Ordnerpfad unterhalb von / sein")
    if not POLICY_TARGET_RE.fullmatch(target_name):
        raise HTTPException(400, "Zielname muss mit Kleinbuchstaben beginnen und darf nur a-z, 0-9, _ und - enthalten")
    if mode not in {"sync", "tar"}:
        raise HTTPException(400, "Ungueltiger Policy-Modus")
    return source_path, target_name, mode


@router.get("/policies", response_class=HTMLResponse)
def policies_page(request: Request):
    require_user(request)
    with db() as connection:
        policies = connection.execute(
            "SELECT p.*,COUNT(DISTINCT c.id) AS client_count,COUNT(DISTINCT pp.id) AS path_count "
            "FROM backup_policies p LEFT JOIN clients c ON c.policy_id=p.id "
            "LEFT JOIN policy_paths pp ON pp.policy_id=p.id GROUP BY p.id ORDER BY p.name"
        ).fetchall()
    defaults = application_settings()
    return render(
        request,
        "policies.html",
        {
            "policies": policies,
            "schedules": {
                policy["id"]: backup_schedule.describe(
                    policy["schedule_hour"], policy["schedule_minute"], policy["interval_hours"],
                    policy["start_offset_minutes"]
                )
                for policy in policies
            },
            "mail_summaries": {policy["id"]: policy_mail_summary(policy) for policy in policies},
            "interval_choices": backup_schedule.INTERVAL_CHOICES,
            "defaults": defaults,
            "cleanup_defaults": checker_cleanup_configuration(),
            "message": request.query_params.get("message", ""),
        },
    )


@router.post("/policies")
def policy_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    schedule_hour: int = Form(...),
    schedule_minute: int = Form(...),
    interval_hours: int = Form(...),
    start_offset_minutes: int = Form(0),
    mariadb_databases_enabled: str | None = Form(None),
    mariadb_users_enabled: str | None = Form(None),
    postgresql_databases_enabled: str | None = Form(None),
    postgresql_roles_enabled: str | None = Form(None),
    mail_on_success: str | None = Form(None),
    mail_on_failure: str | None = Form(None),
    mail_on_skipped: str | None = Form(None),
    cleanup_enabled: str | None = Form(None),
    retention_days: int = Form(7),
    minimum_snapshots_to_keep: int = Form(2),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    name = name.strip()
    if not (3 <= len(name) <= 80):
        raise HTTPException(400, "Policy-Name muss 3 bis 80 Zeichen lang sein")
    schedule_hour, schedule_minute, interval_hours, start_offset_minutes = validated_schedule(
        schedule_hour, schedule_minute, interval_hours, start_offset_minutes
    )
    cleanup_enabled_value, retention_days, minimum_snapshots_to_keep = validated_retention(
        cleanup_enabled, retention_days, minimum_snapshots_to_keep
    )
    try:
        with db() as connection:
            databases_enabled = bool(mariadb_databases_enabled)
            users_enabled = bool(mariadb_users_enabled)
            cursor = connection.execute(
                "INSERT INTO backup_policies(name,description,mariadb_enabled,mariadb_databases_enabled,"
                "mariadb_users_enabled,postgresql_databases_enabled,postgresql_roles_enabled,"
                "schedule_hour,schedule_minute,interval_hours,start_offset_minutes,"
                "mail_on_success,mail_on_failure,mail_on_skipped,cleanup_enabled,retention_days,"
                "minimum_snapshots_to_keep,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (name, description.strip()[:1000], databases_enabled or users_enabled,
                 databases_enabled, users_enabled, bool(postgresql_databases_enabled),
                 bool(postgresql_roles_enabled), schedule_hour, schedule_minute, interval_hours,
                 start_offset_minutes, bool(mail_on_success), bool(mail_on_failure),
                 bool(mail_on_skipped), cleanup_enabled_value, retention_days,
                 minimum_snapshots_to_keep, now_iso(), now_iso()),
            )
            policy_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Policy-Name existiert bereits")
    audit(request, "policy.create", name, f"policy_id={policy_id}", user_id=user["id"])
    return RedirectResponse(f"/policies/{policy_id}", status_code=303)


@router.get("/policies/{policy_id}", response_class=HTMLResponse)
def policy_detail(request: Request, policy_id: int):
    require_user(request)
    with db() as connection:
        policy = connection.execute("SELECT * FROM backup_policies WHERE id=?", (policy_id,)).fetchone()
        paths = connection.execute(
            "SELECT * FROM policy_paths WHERE policy_id=? ORDER BY sort_order,id", (policy_id,)
        ).fetchall()
        clients = connection.execute(
            "SELECT id,slug,source_hostname FROM clients WHERE policy_id=? ORDER BY slug", (policy_id,)
        ).fetchall()
        if not policy:
            raise HTTPException(404)
        copy_name = suggested_copy_name(connection, str(policy["name"]))
    now = datetime.now().astimezone()
    _current, following = backup_schedule.schedule_window(
        now, policy["schedule_hour"], policy["schedule_minute"], policy["interval_hours"]
    )
    return render(
        request,
        "policy_detail.html",
        {
            "policy": policy,
            "paths": paths,
            "clients": clients,
            "interval_choices": backup_schedule.INTERVAL_CHOICES,
            "schedule_description": backup_schedule.describe(
                policy["schedule_hour"], policy["schedule_minute"], policy["interval_hours"],
                policy["start_offset_minutes"]
            ),
            "next_slot": following,
            "copy_name": copy_name,
            "cleanup_defaults": checker_cleanup_configuration(),
            "message": request.query_params.get("message", ""),
        },
    )


@router.post("/policies/{policy_id}")
def policy_update(
    request: Request,
    policy_id: int,
    name: str = Form(...),
    description: str = Form(""),
    schedule_hour: int = Form(...),
    schedule_minute: int = Form(...),
    interval_hours: int = Form(...),
    start_offset_minutes: int = Form(0),
    mariadb_databases_enabled: str | None = Form(None),
    mariadb_users_enabled: str | None = Form(None),
    postgresql_databases_enabled: str | None = Form(None),
    postgresql_roles_enabled: str | None = Form(None),
    mail_on_success: str | None = Form(None),
    mail_on_failure: str | None = Form(None),
    mail_on_skipped: str | None = Form(None),
    cleanup_enabled: str | None = Form(None),
    retention_days: int = Form(7),
    minimum_snapshots_to_keep: int = Form(2),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    name = name.strip()
    if not (3 <= len(name) <= 80):
        raise HTTPException(400, "Policy-Name muss 3 bis 80 Zeichen lang sein")
    schedule_hour, schedule_minute, interval_hours, start_offset_minutes = validated_schedule(
        schedule_hour, schedule_minute, interval_hours, start_offset_minutes
    )
    cleanup_enabled_value, retention_days, minimum_snapshots_to_keep = validated_retention(
        cleanup_enabled, retention_days, minimum_snapshots_to_keep
    )
    try:
        with db() as connection:
            if not connection.execute("SELECT 1 FROM backup_policies WHERE id=?", (policy_id,)).fetchone():
                raise HTTPException(404)
            databases_enabled = bool(mariadb_databases_enabled)
            users_enabled = bool(mariadb_users_enabled)
            connection.execute(
                "UPDATE backup_policies SET name=?,description=?,mariadb_enabled=?,"
                "mariadb_databases_enabled=?,mariadb_users_enabled=?,postgresql_databases_enabled=?,"
                "postgresql_roles_enabled=?,schedule_hour=?,schedule_minute=?,"
                "interval_hours=?,start_offset_minutes=?,mail_on_success=?,mail_on_failure=?,"
                "mail_on_skipped=?,cleanup_enabled=?,retention_days=?,minimum_snapshots_to_keep=?,"
                "updated_at=? WHERE id=?",
                (name, description.strip()[:1000], databases_enabled or users_enabled,
                 databases_enabled, users_enabled, bool(postgresql_databases_enabled),
                 bool(postgresql_roles_enabled), schedule_hour, schedule_minute, interval_hours,
                 start_offset_minutes, bool(mail_on_success), bool(mail_on_failure),
                 bool(mail_on_skipped), cleanup_enabled_value, retention_days,
                 minimum_snapshots_to_keep, now_iso(), policy_id),
            )
            connection.execute(
                "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE policy_id=?",
                (now_iso(), policy_id),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Policy-Name existiert bereits")
    audit(request, "policy.update", name, f"policy_id={policy_id}", user_id=user["id"])
    return RedirectResponse(f"/policies/{policy_id}", status_code=303)


POLICY_NAME_MAX = 80


def policy_name_with_suffix(name: str, suffix: str) -> str:
    """Append a suffix and keep the result inside the allowed name length."""
    return f"{name[:POLICY_NAME_MAX - len(suffix)].rstrip()}{suffix}"


def suggested_copy_name(connection: sqlite3.Connection, name: str) -> str:
    """Return an unused name for a copy of the given policy."""
    candidate = policy_name_with_suffix(name, " (Kopie)")
    counter = 2
    while connection.execute("SELECT 1 FROM backup_policies WHERE name=?", (candidate,)).fetchone():
        candidate = policy_name_with_suffix(name, f" (Kopie {counter})")
        counter += 1
        if counter > 99:
            raise HTTPException(409, "Es existieren bereits zu viele Kopien dieser Policy")
    return candidate


@router.post("/policies/{policy_id}/duplicate")
def policy_duplicate(
    request: Request, policy_id: int, name: str = Form(""), csrf_token: str = Form(...)
):
    """Copy a policy including its path rules, but without its server assignments."""
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    try:
        with db() as connection:
            source = connection.execute(
                "SELECT * FROM backup_policies WHERE id=?", (policy_id,)
            ).fetchone()
            if not source:
                raise HTTPException(404)
            new_name = name.strip() or suggested_copy_name(connection, str(source["name"]))
            if not (3 <= len(new_name) <= POLICY_NAME_MAX):
                raise HTTPException(400, f"Policy-Name muss 3 bis {POLICY_NAME_MAX} Zeichen lang sein")
            cursor = connection.execute(
                "INSERT INTO backup_policies(name,description,mariadb_enabled,mariadb_databases_enabled,"
                "mariadb_users_enabled,postgresql_databases_enabled,postgresql_roles_enabled,"
                "schedule_hour,schedule_minute,interval_hours,start_offset_minutes,"
                "mail_on_success,mail_on_failure,mail_on_skipped,cleanup_enabled,retention_days,"
                "minimum_snapshots_to_keep,active,created_at,updated_at) "
                "SELECT ?,description,mariadb_enabled,mariadb_databases_enabled,mariadb_users_enabled,"
                "postgresql_databases_enabled,postgresql_roles_enabled,"
                "schedule_hour,schedule_minute,interval_hours,start_offset_minutes,mail_on_success,"
                "mail_on_failure,mail_on_skipped,cleanup_enabled,retention_days,minimum_snapshots_to_keep,"
                "active,?,? FROM backup_policies WHERE id=?",
                (new_name, now_iso(), now_iso(), policy_id),
            )
            new_id = int(cursor.lastrowid)
            connection.execute(
                "INSERT INTO policy_paths(policy_id,source_path,target_name,mode,sort_order) "
                "SELECT ?,source_path,target_name,mode,sort_order FROM policy_paths WHERE policy_id=?",
                (new_id, policy_id),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "Policy-Name existiert bereits") from exc
    audit(request, "policy.duplicate", new_name, f"source_policy_id={policy_id}", user_id=user["id"])
    message = f"Kopie von „{source['name']}“ angelegt; noch keinem Server zugewiesen"
    return RedirectResponse(f"/policies/{new_id}?message={quote(message)}", status_code=303)


@router.post("/policies/{policy_id}/delete")
def policy_delete(request: Request, policy_id: int, csrf_token: str = Form(...)):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    try:
        with db() as connection:
            # Lock writers before checking the assignment so a concurrent client
            # update cannot attach the policy between the check and the delete.
            connection.execute("BEGIN IMMEDIATE")
            policy = connection.execute(
                "SELECT name FROM backup_policies WHERE id=?", (policy_id,)
            ).fetchone()
            if not policy:
                raise HTTPException(404)
            client_count = connection.execute(
                "SELECT COUNT(*) FROM clients WHERE policy_id=?", (policy_id,)
            ).fetchone()[0]
            if client_count:
                raise HTTPException(
                    409,
                    "Policy wird noch von mindestens einem Server verwendet und kann nicht geloescht werden",
                )
            deleted = connection.execute(
                "DELETE FROM backup_policies WHERE id=?", (policy_id,)
            ).rowcount
            if deleted != 1:
                raise HTTPException(404)
            policy_name = str(policy["name"])
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            409,
            "Policy wird noch verwendet und kann nicht geloescht werden",
        ) from exc
    audit(request, "policy.delete", policy_name, f"policy_id={policy_id}", user_id=user["id"])
    return RedirectResponse(
        f"/policies?message={quote('Backup-Policy wurde gelöscht')}", status_code=303
    )


@router.post("/policies/{policy_id}/paths")
def policy_path_add(
    request: Request,
    policy_id: int,
    source_path: str = Form(...),
    target_name: str = Form(...),
    mode: str = Form(...),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    source_path, target_name, mode = validated_policy_path(source_path, target_name, mode)
    try:
        with db() as connection:
            if not connection.execute("SELECT 1 FROM backup_policies WHERE id=?", (policy_id,)).fetchone():
                raise HTTPException(404)
            order = connection.execute(
                "SELECT COALESCE(MAX(sort_order),0)+10 FROM policy_paths WHERE policy_id=?", (policy_id,)
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO policy_paths(policy_id,source_path,target_name,mode,sort_order) VALUES(?,?,?,?,?)",
                (policy_id, source_path, target_name, mode, order),
            )
            connection.execute("UPDATE backup_policies SET updated_at=? WHERE id=?", (now_iso(), policy_id))
            connection.execute(
                "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE policy_id=?",
                (now_iso(), policy_id),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Quellpfad oder Zielname existiert in dieser Policy bereits")
    audit(request, "policy.path_add", str(policy_id), f"{source_path} mode={mode}", user_id=user["id"])
    return RedirectResponse(f"/policies/{policy_id}", status_code=303)


@router.post("/policies/{policy_id}/paths/{path_id}/delete")
def policy_path_delete(request: Request, policy_id: int, path_id: int, csrf_token: str = Form(...)):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    with db() as connection:
        deleted = connection.execute(
            "DELETE FROM policy_paths WHERE id=? AND policy_id=?", (path_id, policy_id)
        ).rowcount
        if not deleted:
            raise HTTPException(404)
        connection.execute("UPDATE backup_policies SET updated_at=? WHERE id=?", (now_iso(), policy_id))
        connection.execute(
            "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE policy_id=?",
            (now_iso(), policy_id),
        )
    audit(request, "policy.path_delete", str(policy_id), f"path_id={path_id}", user_id=user["id"])
    return RedirectResponse(f"/policies/{policy_id}", status_code=303)
