"""Mirror targets and their runs."""

from __future__ import annotations

import sqlite3
import subprocess
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

import mirror as mirror_module

from core import HOME_ROOT, db, encrypt_deployment_token, format_size, now_iso, parsed_timestamp
from auth import audit, require_user, verify_csrf
from rendering import render
from workers import MIRROR_WAKEUP


router = APIRouter()


def mirror_target_view(target: sqlite3.Row) -> dict[str, Any]:
    """Enrich a mirror target with the values the templates display."""
    item = dict(target)
    item["key_configured"] = bool(str(target["private_key_ciphertext"] or ""))
    item["host_key_configured"] = bool(str(target["host_key"] or "").strip())
    item["ready"] = item["key_configured"] and item["host_key_configured"]
    item["free"] = format_size(target["free_bytes"]) if target["free_bytes"] is not None else "–"
    item["total"] = format_size(target["total_bytes"]) if target["total_bytes"] is not None else "–"
    total = int(target["total_bytes"] or 0)
    free = int(target["free_bytes"] or 0)
    item["free_percent"] = round(free / total * 100, 1) if total else None
    item["used_percent"] = round((total - free) / total * 100, 1) if total else 0
    item["strategy_text"] = mirror_module.STRATEGIES.get(str(target["strategy"]), str(target["strategy"]))
    item["interval_text"] = mirror_module.describe_interval(int(target["interval_hours"]))
    item["interval_value"], item["interval_unit"] = mirror_module.interval_fields(
        int(target["interval_hours"])
    )
    item["next_run_display"] = (
        parsed_timestamp(target["next_run_at"]).astimezone().strftime("%d.%m.%Y %H:%M")
        if target["next_run_at"] and target["enabled"] else "–"
    )
    return item


def enqueue_mirror_run(target_id: int, mode: str, requested_by: int | None = None) -> int | None:
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        target = connection.execute(
            "SELECT * FROM mirror_targets WHERE id=?", (target_id,)
        ).fetchone()
        if not target:
            raise HTTPException(404)
        if not str(target["private_key_ciphertext"] or "") or not str(target["host_key"] or "").strip():
            raise HTTPException(409, "Privater Schluessel und Hostschluessel muessen hinterlegt sein")
        if connection.execute(
            "SELECT 1 FROM mirror_runs WHERE target_id=? AND status IN ('queued','running')",
            (target_id,),
        ).fetchone():
            return None
        cursor = connection.execute(
            "INSERT INTO mirror_runs(target_id,mode,status,requested_by,requested_at) VALUES(?,?,'queued',?,?)",
            (target_id, mode, requested_by, now_iso()),
        )
        run_id = int(cursor.lastrowid)
    MIRROR_WAKEUP.set()
    return run_id


@router.get("/mirrors", response_class=HTMLResponse)
def mirrors_page(request: Request):
    require_user(request, admin=True)
    with db() as connection:
        targets = connection.execute("SELECT * FROM mirror_targets ORDER BY name").fetchall()
        runs = connection.execute(
            "SELECT r.*,t.name AS target_name FROM mirror_runs r "
            "JOIN mirror_targets t ON t.id=r.target_id ORDER BY r.id DESC LIMIT 20"
        ).fetchall()
    return render(request, "mirrors.html", {
        "targets": [mirror_target_view(target) for target in targets],
        "runs": runs,
        "default_options": mirror_module.DEFAULT_RSYNC_OPTIONS,
        "max_interval_days": mirror_module.MAX_INTERVAL_HOURS // 24,
        "history_options": mirror_module.HISTORY_RSYNC_OPTIONS,
        "strategies": mirror_module.STRATEGIES,
        "default_strategy": mirror_module.DEFAULT_STRATEGY,
        "source_path": str(HOME_ROOT),
        "message": request.query_params.get("message", ""),
    })


@router.post("/mirrors")
def mirror_create(
    request: Request,
    name: str = Form(...),
    host: str = Form(...),
    ssh_port: int = Form(22),
    username: str = Form(...),
    remote_path: str = Form(...),
    private_key: str = Form(...),
    rsync_options: str = Form(mirror_module.DEFAULT_RSYNC_OPTIONS),
    interval_value: int = Form(24),
    interval_unit: str = Form("hours"),
    retention_days: int = Form(0),
    strategy: str = Form(mirror_module.DEFAULT_STRATEGY),
    enabled: str | None = Form(None),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    name = name.strip()
    if not (3 <= len(name) <= 60):
        raise HTTPException(400, "Name muss 3 bis 60 Zeichen lang sein")
    try:
        values = mirror_module.validated_target(
            host=host, username=username, remote_path=remote_path, ssh_port=ssh_port,
            interval_hours=mirror_module.interval_from_unit(interval_value, interval_unit),
            retention_days=retention_days, rsync_options=rsync_options, strategy=strategy,
        )
        key = mirror_module.normalized_private_key(private_key)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    try:
        with db() as connection:
            cursor = connection.execute(
                "INSERT INTO mirror_targets(name,host,ssh_port,username,remote_path,private_key_ciphertext,"
                "rsync_options,strategy,interval_hours,retention_days,enabled,updated_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    name, values["host"], values["ssh_port"], values["username"], values["remote_path"],
                    encrypt_deployment_token(key), values["rsync_options"], values["strategy"],
                    values["interval_hours"], values["retention_days"], bool(enabled), user["id"],
                    now_iso(), now_iso(),
                ),
            )
            target_id = int(cursor.lastrowid)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Ein Spiegelziel mit diesem Namen existiert bereits")
    audit(request, "mirror.create", name, f"host={values['host']}", user_id=user["id"])
    return RedirectResponse(
        f"/mirrors/{target_id}?message={quote('Spiegelziel angelegt; jetzt den Hostschlüssel abrufen')}",
        status_code=303,
    )


@router.get("/mirrors/{target_id}", response_class=HTMLResponse)
def mirror_detail(request: Request, target_id: int):
    require_user(request, admin=True)
    with db() as connection:
        target = connection.execute("SELECT * FROM mirror_targets WHERE id=?", (target_id,)).fetchone()
        if not target:
            raise HTTPException(404)
        runs = connection.execute(
            "SELECT r.*,u.username AS requested_by_name FROM mirror_runs r "
            "LEFT JOIN users u ON u.id=r.requested_by WHERE r.target_id=? ORDER BY r.id DESC LIMIT 30",
            (target_id,),
        ).fetchall()
        active = connection.execute(
            "SELECT 1 FROM mirror_runs WHERE target_id=? AND status IN ('queued','running')",
            (target_id,),
        ).fetchone()
    return render(request, "mirror_detail.html", {
        "target": mirror_target_view(target),
        "max_interval_days": mirror_module.MAX_INTERVAL_HOURS // 24,
        "strategies": mirror_module.STRATEGIES,
        "runs": runs,
        "busy": bool(active),
        "source_path": str(HOME_ROOT),
        "message": request.query_params.get("message", ""),
    })


@router.post("/mirrors/{target_id}")
def mirror_update(
    request: Request,
    target_id: int,
    name: str = Form(...),
    host: str = Form(...),
    ssh_port: int = Form(22),
    username: str = Form(...),
    remote_path: str = Form(...),
    private_key: str = Form(""),
    rsync_options: str = Form(mirror_module.DEFAULT_RSYNC_OPTIONS),
    interval_value: int = Form(24),
    interval_unit: str = Form("hours"),
    retention_days: int = Form(0),
    strategy: str = Form(mirror_module.DEFAULT_STRATEGY),
    enabled: str | None = Form(None),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    name = name.strip()
    if not (3 <= len(name) <= 60):
        raise HTTPException(400, "Name muss 3 bis 60 Zeichen lang sein")
    try:
        values = mirror_module.validated_target(
            host=host, username=username, remote_path=remote_path, ssh_port=ssh_port,
            interval_hours=mirror_module.interval_from_unit(interval_value, interval_unit),
            retention_days=retention_days, rsync_options=rsync_options, strategy=strategy,
        )
        key = mirror_module.normalized_private_key(private_key) if private_key.strip() else ""
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    try:
        with db() as connection:
            current = connection.execute(
                "SELECT * FROM mirror_targets WHERE id=?", (target_id,)
            ).fetchone()
            if not current:
                raise HTTPException(404)
            # A changed address invalidates the pinned host key.
            address_changed = (
                values["host"] != str(current["host"]) or values["ssh_port"] != int(current["ssh_port"])
            )
            connection.execute(
                "UPDATE mirror_targets SET name=?,host=?,ssh_port=?,username=?,remote_path=?,"
                "rsync_options=?,strategy=?,interval_hours=?,retention_days=?,enabled=?,"
                "private_key_ciphertext=CASE WHEN ?<>'' THEN ? ELSE private_key_ciphertext END,"
                "host_key=CASE WHEN ? THEN '' ELSE host_key END,"
                "updated_by=?,updated_at=? WHERE id=?",
                (
                    name, values["host"], values["ssh_port"], values["username"], values["remote_path"],
                    values["rsync_options"], values["strategy"], values["interval_hours"],
                    values["retention_days"], bool(enabled), key, encrypt_deployment_token(key) if key else "",
                    address_changed, user["id"], now_iso(), target_id,
                ),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Ein Spiegelziel mit diesem Namen existiert bereits")
    audit(
        request, "mirror.update", name, f"host={values['host']} strategy={values['strategy']}",
        user_id=user["id"],
    )
    message = "Spiegelziel gespeichert"
    if address_changed:
        message += "; die Adresse hat sich geändert, bitte den Hostschlüssel neu abrufen"
    return RedirectResponse(f"/mirrors/{target_id}?message={quote(message)}", status_code=303)


@router.post("/mirrors/{target_id}/host-key")
def mirror_host_key(request: Request, target_id: int, csrf_token: str = Form(...)):
    """Pin the target's host key so the replication can verify it later."""
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    with db() as connection:
        target = connection.execute("SELECT * FROM mirror_targets WHERE id=?", (target_id,)).fetchone()
    if not target:
        raise HTTPException(404)
    process = subprocess.run(
        ["/usr/bin/ssh-keyscan", "-T", "15", "-p", str(int(target["ssh_port"])),
         "-t", "ed25519,rsa,ecdsa", str(target["host"])],
        capture_output=True, text=True, errors="replace", timeout=45, check=False,
    )
    try:
        host_key = mirror_module.normalized_host_key(
            process.stdout, str(target["host"]), int(target["ssh_port"])
        )
    except ValueError as exc:
        detail = (process.stderr or "").strip()[-300:]
        raise HTTPException(502, f"Hostschluessel konnte nicht gelesen werden: {exc}. {detail}") from exc
    with db() as connection:
        connection.execute(
            "UPDATE mirror_targets SET host_key=?,updated_by=?,updated_at=? WHERE id=?",
            (host_key, user["id"], now_iso(), target_id),
        )
    fingerprints = " · ".join(line.split()[1] + " " + line.split()[2][:24] for line in host_key.splitlines())
    audit(request, "mirror.host_key", str(target["name"]), fingerprints[:200], user_id=user["id"])
    return RedirectResponse(
        f"/mirrors/{target_id}?message={quote('Hostschlüssel übernommen: ' + fingerprints[:120])}",
        status_code=303,
    )


@router.post("/mirrors/{target_id}/run")
def mirror_run_trigger(request: Request, target_id: int, csrf_token: str = Form(...)):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    run_id = enqueue_mirror_run(target_id, "manual", user["id"])
    message = (
        f"Replikation gestartet (Lauf #{run_id})" if run_id
        else "Für dieses Ziel läuft bereits eine Replikation"
    )
    audit(request, "mirror.trigger", str(target_id), f"run_id={run_id}", user_id=user["id"])
    return RedirectResponse(f"/mirrors/{target_id}?message={quote(message)}", status_code=303)


@router.post("/mirrors/{target_id}/delete")
def mirror_delete(request: Request, target_id: int, csrf_token: str = Form(...)):
    """Forget a mirror target; the data already replicated stays on the remote."""
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    with db() as connection:
        target = connection.execute(
            "SELECT name FROM mirror_targets WHERE id=?", (target_id,)
        ).fetchone()
        if not target:
            raise HTTPException(404)
        if connection.execute(
            "SELECT 1 FROM mirror_runs WHERE target_id=? AND status='running'", (target_id,)
        ).fetchone():
            raise HTTPException(409, "Es laeuft gerade eine Replikation auf dieses Ziel")
        connection.execute("DELETE FROM mirror_targets WHERE id=?", (target_id,))
    audit(request, "mirror.delete", str(target["name"]), user_id=user["id"])
    return RedirectResponse(
        f"/mirrors?message={quote('Spiegelziel entfernt; die replizierten Daten bleiben auf dem Zielserver')}",
        status_code=303,
    )


@router.get("/mirrors/runs/{run_id}/output")
def mirror_run_output(request: Request, run_id: int):
    """Serve the current output so a running replication can be followed live."""
    require_user(request, admin=True)
    with db() as connection:
        run = connection.execute(
            "SELECT status,output,summary,finished_at,transferred_bytes FROM mirror_runs WHERE id=?",
            (run_id,),
        ).fetchone()
    if not run:
        raise HTTPException(404)
    return JSONResponse({
        "status": str(run["status"]),
        "running": str(run["status"]) in {"queued", "running"},
        "output": str(run["output"] or ""),
        "summary": str(run["summary"] or ""),
        "finished_at": run["finished_at"],
        "volume": format_size(run["transferred_bytes"]),
    })


@router.get("/mirrors/runs/{run_id}", response_class=HTMLResponse)
def mirror_run_detail(request: Request, run_id: int):
    require_user(request, admin=True)
    with db() as connection:
        run = connection.execute(
            "SELECT r.*,t.name AS target_name,t.host,u.username AS requested_by_name FROM mirror_runs r "
            "JOIN mirror_targets t ON t.id=r.target_id LEFT JOIN users u ON u.id=r.requested_by "
            "WHERE r.id=?",
            (run_id,),
        ).fetchone()
    if not run:
        raise HTTPException(404)
    return render(request, "mirror_run.html", {"run": run, "volume": format_size(run["transferred_bytes"])})
