"""Source servers: onboarding, detail pages and deployment tokens."""

from __future__ import annotations

import json
import os
import pwd
import secrets
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from core import (
    HOME_ROOT, HOST_RE, USERNAME_RE, application_settings, client_already_deployed, db,
    decrypt_deployment_token, encrypt_deployment_token, format_size, now_iso, now_ts,
    parsed_timestamp, system_account_exists, token_hash,
)
from auth import audit, require_user, verify_csrf
from rendering import checker_results, policy_mail_summary, render
from workers import client_schedule_state, policy_payload


router = APIRouter()


def active_policies() -> list[sqlite3.Row]:
    with db() as connection:
        return connection.execute(
            "SELECT * FROM backup_policies WHERE active=1 ORDER BY name"
        ).fetchall()


@router.get("/clients/new", response_class=HTMLResponse)
def client_new_page(request: Request):
    require_user(request, admin=True)
    return render(
        request,
        "client_new.html",
        {"error": "", "defaults": application_settings(), "policies": active_policies()},
    )


def provision_system_user(username: str, home: Path) -> None:
    try:
        existing = pwd.getpwnam(username)
        if Path(existing.pw_dir) != home:
            raise RuntimeError(f"Systembenutzer existiert mit anderem Home: {existing.pw_dir}")
    except KeyError:
        subprocess.run(
            ["/usr/sbin/useradd", "--create-home", "--home-dir", str(home), "--shell", "/bin/sh", username],
            check=True,
            capture_output=True,
            text=True,
        )
    account = pwd.getpwnam(username)
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    os.chown(home, account.pw_uid, account.pw_gid)
    os.chown(ssh_dir, account.pw_uid, account.pw_gid)
    os.chmod(home, 0o700)
    os.chmod(ssh_dir, 0o700)


@router.post("/clients/new", response_class=HTMLResponse)
def client_create(
    request: Request,
    slug: str = Form(...),
    source_hostname: str = Form(""),
    policy_id: int = Form(...),
    agent_log_level: str = Form("INFO"),
    agent_log_local: str | None = Form(None),
    agent_log_portal: str | None = Form(None),
    agent_log_traceback: str | None = Form(None),
    agent_log_max_kb: int = Form(256),
    run_initial_backup: str | None = Form(None),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    settings = application_settings()
    slug = slug.strip().lower()
    source_hostname = source_hostname.strip()
    if not USERNAME_RE.fullmatch(slug):
        return render(request, "client_new.html", {"error": "Slug muss 2–24 sichere Kleinbuchstaben/Ziffern enthalten.", "defaults": settings, "policies": active_policies()}, 400)
    if source_hostname and not HOST_RE.fullmatch(source_hostname):
        return render(request, "client_new.html", {"error": "Quellhostname ist ungueltig.", "defaults": settings, "policies": active_policies()}, 400)
    agent_log_level = agent_log_level.upper().strip()
    if agent_log_level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise HTTPException(400, "Ungueltiger Agent-Loglevel")
    if not 16 <= agent_log_max_kb <= 512:
        raise HTTPException(400, "Agent-Portallog muss zwischen 16 und 512 KB liegen")
    prefix = str(settings["username_prefix"])
    username = prefix + slug
    if len(username) > 31:
        raise HTTPException(400, "Systembenutzername ist zu lang")
    home = HOME_ROOT / username
    with db() as connection:
        if not connection.execute(
            "SELECT 1 FROM backup_policies WHERE id=? AND active=1", (policy_id,)
        ).fetchone():
            raise HTTPException(400, "Ungueltige Backup-Policy")
        if connection.execute("SELECT 1 FROM clients WHERE slug=? OR username=?", (slug, username)).fetchone():
            raise HTTPException(409, "Client existiert bereits")
    provision_system_user(username, home)
    with db() as connection:
        cursor = connection.execute(
            "INSERT INTO clients(slug,username,source_hostname,home_path,policy_id,"
            "agent_log_level,agent_log_local,agent_log_portal,"
            "agent_log_traceback,agent_log_max_bytes,run_initial_backup,agent_config_updated_at,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                slug, username, source_hostname or None, str(home), policy_id,
                agent_log_level, bool(agent_log_local),
                bool(agent_log_portal), bool(agent_log_traceback), agent_log_max_kb * 1024,
                bool(run_initial_backup), now_iso(), now_iso(),
            ),
        )
        client_id = cursor.lastrowid
    audit(request, "client.create", slug, f"username={username}")
    return RedirectResponse(f"/clients/{client_id}", status_code=303)


@router.get("/clients/{client_id}", response_class=HTMLResponse)
def client_detail(request: Request, client_id: int):
    require_user(request)
    with db() as connection:
        client = connection.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        events = connection.execute("SELECT * FROM status_events WHERE client_id=? ORDER BY id DESC LIMIT 20", (client_id,)).fetchall()
        active_deployment = connection.execute(
            "SELECT expires_at,rotate_ssh_key FROM deployment_tokens WHERE client_id=? AND used_at IS NULL "
            "AND expires_at>=? AND token_ciphertext IS NOT NULL ORDER BY created_at DESC LIMIT 1",
            (client_id, now_ts()),
        ).fetchone()
        commands = connection.execute(
            "SELECT * FROM backup_commands WHERE client_id=? ORDER BY id DESC LIMIT 20",
            (client_id,),
        ).fetchall()
        run_log_rows = connection.execute(
            "SELECT id,run_id,status,source_hostname,phase,finished_at,log_level,log_bytes,truncated,received_at "
            "FROM backup_run_logs WHERE client_id=? ORDER BY id DESC LIMIT 20",
            (client_id,),
        ).fetchall()
        run_logs = []
        for row in run_log_rows:
            item = dict(row)
            item["log_size"] = format_size(item["log_bytes"])
            run_logs.append(item)
        active_command = connection.execute(
            "SELECT * FROM backup_commands WHERE client_id=? AND status IN ('queued','claimed','running') "
            "ORDER BY id DESC LIMIT 1",
            (client_id,),
        ).fetchone()
        policy = connection.execute("SELECT * FROM backup_policies WHERE id=?", (client["policy_id"],)).fetchone() if client else None
        policy_paths = connection.execute(
            "SELECT * FROM policy_paths WHERE policy_id=? ORDER BY sort_order,id", (client["policy_id"],)
        ).fetchall() if client else []
        policies = connection.execute(
            "SELECT * FROM backup_policies WHERE active=1 ORDER BY name"
        ).fetchall()
        if not client:
            raise HTTPException(404)
        schedule_state = client_schedule_state(connection, client)
    result = checker_results().get(client["username"], {}).get("result", {})
    try:
        agent_payload = json.loads(client["last_payload"] or "{}")
    except (TypeError, json.JSONDecodeError):
        agent_payload = {}
    last_poll = parsed_timestamp(client["last_poll_at"])
    agent_online = bool(last_poll and (datetime.now().astimezone() - last_poll).total_seconds() <= 180)
    backup_running = bool(active_command and active_command["status"] in {"claimed", "running"}) or client["last_event"] == "started"
    return render(
        request,
        "client_detail.html",
        {
            "client": dict(client),
            "events": events,
            "result": result,
            "agent_payload": agent_payload,
            "agent_volume": format_size(agent_payload.get("logical_run_bytes")),
            "active_deployment": dict(active_deployment) if active_deployment else None,
            "already_deployed": client_already_deployed(client),
            "commands": commands,
            "run_logs": run_logs,
            "active_command": dict(active_command) if active_command else None,
            "agent_online": agent_online,
            "backup_running": backup_running,
            "policy": dict(policy) if policy else None,
            "policy_paths": policy_paths,
            "policy_mail_summary": policy_mail_summary(policy) if policy else "unbekannt",
            "retention_summary": (
                f"{int(policy['retention_days'])} Tage; mindestens {int(policy['minimum_snapshots_to_keep'])} Stände"
                if policy and policy["cleanup_enabled"] else "Cleanup deaktiviert"
            ),
            "storage_size": format_size(client["storage_bytes"]),
            "storage_checked_at": client["storage_checked_at"],
            "storage_error": client["storage_error"],
            "policies": policies,
            "schedule": schedule_state,
            "account_exists": system_account_exists(client["username"]),
            "home_exists": Path(client["home_path"]).is_dir(),
            "message": request.query_params.get("message", ""),
        },
    )


@router.post("/clients/{client_id}/agent-config")
def client_agent_config_update(
    request: Request,
    client_id: int,
    agent_log_level: str = Form("INFO"),
    agent_log_local: str | None = Form(None),
    agent_log_portal: str | None = Form(None),
    agent_log_traceback: str | None = Form(None),
    agent_log_max_kb: int = Form(256),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    level = agent_log_level.upper().strip()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR"} or not 16 <= agent_log_max_kb <= 512:
        raise HTTPException(400, "Ungueltige Agent-Konfiguration")
    with db() as connection:
        updated = connection.execute(
            "UPDATE clients SET agent_log_level=?,agent_log_local=?,"
            "agent_log_portal=?,agent_log_traceback=?,agent_log_max_bytes=?,"
            "agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE id=?",
            (
                level, bool(agent_log_local),
                bool(agent_log_portal), bool(agent_log_traceback), agent_log_max_kb * 1024,
                now_iso(), client_id,
            ),
        ).rowcount
    if not updated:
        raise HTTPException(404)
    audit(request, "client.agent_config", str(client_id), f"level={level} portal_log={bool(agent_log_portal)}", user_id=user["id"])
    return RedirectResponse(f"/clients/{client_id}", status_code=303)


@router.get("/clients/{client_id}/logs/{log_id}", response_class=HTMLResponse)
def client_run_log_detail(request: Request, client_id: int, log_id: int):
    require_user(request, admin=True)
    with db() as connection:
        client = connection.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        run_log = connection.execute(
            "SELECT * FROM backup_run_logs WHERE id=? AND client_id=?", (log_id, client_id)
        ).fetchone()
    if not client or not run_log:
        raise HTTPException(404)
    try:
        report = json.loads(run_log["report_json"] or "{}")
    except json.JSONDecodeError:
        report = {}
    return render(
        request,
        "run_log_detail.html",
        {"client": dict(client), "run_log": dict(run_log), "report": report, "log_size": format_size(run_log["log_bytes"])},
    )


@router.post("/clients/{client_id}/policy")
def client_policy_assign(
    request: Request, client_id: int, policy_id: int = Form(...), csrf_token: str = Form(...)
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    with db() as connection:
        client = connection.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        policy = connection.execute(
            "SELECT * FROM backup_policies WHERE id=? AND active=1", (policy_id,)
        ).fetchone()
        if not client or not policy:
            raise HTTPException(404)
        previous_policy_id = int(client["policy_id"])
        if previous_policy_id == policy_id:
            return RedirectResponse(
                f"/clients/{client_id}?message={quote('Diese Policy ist bereits zugewiesen')}", status_code=303
            )
        connection.execute(
            "UPDATE clients SET policy_id=?,agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE id=?",
            (policy_id, now_iso(), client_id),
        )
    audit(
        request, "client.policy_assign", client["slug"],
        f"old_policy_id={previous_policy_id} new_policy_id={policy_id} policy={policy['name']}", user_id=user["id"],
    )
    return RedirectResponse(
        f"/clients/{client_id}?message={quote('Backup-Policy wurde zugewiesen')}", status_code=303
    )


@router.post("/clients/{client_id}/hostname")
def client_hostname_update(
    request: Request, client_id: int, source_hostname: str = Form(...), csrf_token: str = Form(...)
):
    """Accept a renamed source server without onboarding it again.

    The agent pins the hostname it was deployed for and the portal refuses polls
    from any other name. Changing it here bumps the configuration version, so
    the agent's next poll under the new name passes and receives a config that
    expects the new name as well; token, SSH key and backups stay as they are.
    """
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    hostname = source_hostname.strip()
    if not HOST_RE.fullmatch(hostname):
        raise HTTPException(400, "Ungueltiger Hostname")
    with db() as connection:
        client = connection.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not client:
            raise HTTPException(404)
        previous = client["source_hostname"]
        if previous == hostname:
            return RedirectResponse(
                f"/clients/{client_id}?message={quote('Der Hostname ist bereits hinterlegt')}", status_code=303
            )
        connection.execute(
            "UPDATE clients SET source_hostname=?,reported_hostname=NULL,reported_hostname_at=NULL,"
            "agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE id=?",
            (hostname, now_iso(), client_id),
        )
    audit(request, "client.hostname", str(client["slug"]), f"old={previous} new={hostname}", user_id=user["id"])
    return RedirectResponse(
        f"/clients/{client_id}?message={quote('Quellhostname geändert; der Agent übernimmt ihn beim nächsten Poll')}",
        status_code=303,
    )


@router.post("/clients/{client_id}/delete")
def client_delete(request: Request, client_id: int, csrf_token: str = Form(...)):
    """Remove a server whose Linux target account no longer exists.

    As long as the account is present the entry is authoritative: the agent may
    still deliver, and the startup import would recreate the row anyway. Only an
    orphaned entry can be dropped, and only from the database — whatever is left
    in the home directory stays untouched.
    """
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    with db() as connection:
        client = connection.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not client:
            raise HTTPException(404)
        username = str(client["username"])
        if system_account_exists(username):
            raise HTTPException(
                409,
                f"Systemkonto {username} existiert noch; der Server kann erst nach dem Entfernen des Kontos "
                "aus dem Portal geloescht werden",
            )
        connection.execute("DELETE FROM clients WHERE id=?", (client_id,))
    home_left = Path(str(client["home_path"])).is_dir()
    audit(
        request, "client.delete", str(client["slug"]),
        f"username={username} home_left={home_left}", user_id=user["id"],
    )
    message = f"Server {client['slug']} wurde aus dem Portal entfernt"
    if home_left:
        message += f"; {client['home_path']} enthält weiterhin Daten und bleibt unverändert"
    return RedirectResponse(f"/?message={quote(message)}", status_code=303)


@router.post("/clients/{client_id}/backup/trigger")
def trigger_backup(
    request: Request,
    client_id: int,
    csrf_token: str = Form(...),
    force: str | None = Form(None),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    forced = bool(force)
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        client = connection.execute("SELECT * FROM clients WHERE id=? AND active=1", (client_id,)).fetchone()
        if not client:
            raise HTTPException(404)
        if not client["agent_token_hash"]:
            raise HTTPException(409, "Client muss zuerst onboarded werden")
        if connection.execute(
            "SELECT 1 FROM policy_cleanup_runs WHERE policy_id=? AND status IN ('queued','running')",
            (client["policy_id"],),
        ).fetchone():
            raise HTTPException(409, "Für diese Policy läuft gerade ein Cleanup")
        active = connection.execute(
            "SELECT * FROM backup_commands WHERE client_id=? AND status IN ('queued','claimed','running')",
            (client_id,),
        ).fetchone()
        if active or client["last_event"] == "started":
            raise HTTPException(409, "Backup ist bereits queued oder aktiv")
        schedule_state = client_schedule_state(connection, client)
        cursor = connection.execute(
            "INSERT INTO backup_commands(client_id,reason,status,force,due_at,policy_snapshot,"
            "requested_by,requested_at) VALUES(?, 'manual', 'queued', ?, ?, ?, ?, ?)",
            (
                client_id,
                forced,
                schedule_state["current_slot"],
                json.dumps(policy_payload(connection, client["policy_id"]), ensure_ascii=False),
                user["id"],
                now_iso(),
            ),
        )
        command_id = cursor.lastrowid
    audit(request, "backup.trigger", client["slug"], f"command_id={command_id} force={forced}", user_id=user["id"])
    message = (
        "Backup wurde beauftragt"
        if forced
        else "Backup wurde beauftragt; der Agent lehnt es ab, solange das Intervall noch nicht abgelaufen ist"
    )
    return RedirectResponse(f"/clients/{client_id}?message={quote(message)}", status_code=303)


def build_deployment_command(raw: str) -> str:
    base = str(application_settings()["public_base_url"]).rstrip("/")
    return (
        f"curl -fsS --retry 3 --retry-all-errors --proto '=https' --tlsv1.2 "
        f"'{base}/bootstrap' -H 'Authorization: Bearer {raw}' | python3"
    )


@router.post("/clients/{client_id}/token", response_class=HTMLResponse)
def create_deployment_token(
    request: Request,
    client_id: int,
    csrf_token: str = Form(...),
    run_initial_backup: str | None = Form(None),
    rotate_ssh_key: str | None = Form(None),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    raw = secrets.token_urlsafe(32)
    minutes = int(application_settings()["deployment_token_minutes"])
    with db() as connection:
        client = connection.execute("SELECT * FROM clients WHERE id=? AND active=1", (client_id,)).fetchone()
        if not client:
            raise HTTPException(404)
        start_immediately = bool(run_initial_backup)
        # A fresh key pair only makes sense for a source that already holds one;
        # a first deployment generates its key anyway.
        rotate_key = bool(rotate_ssh_key) and client_already_deployed(client)
        connection.execute(
            "UPDATE clients SET run_initial_backup=? WHERE id=?",
            (start_immediately, client_id),
        )
        connection.execute("DELETE FROM deployment_tokens WHERE client_id=? AND used_at IS NULL", (client_id,))
        connection.execute(
            "INSERT INTO deployment_tokens(token_hash,client_id,token_ciphertext,expires_at,rotate_ssh_key,"
            "created_by,created_at) VALUES(?,?,?,?,?,?,?)",
            (
                token_hash(raw),
                client_id,
                encrypt_deployment_token(raw),
                now_ts() + minutes * 60,
                rotate_key,
                user["id"],
                now_iso(),
            ),
        )
        client = connection.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    audit(
        request,
        "deployment_token.create",
        client["slug"],
        f"expires={minutes}m initial_backup={start_immediately} rotate_ssh_key={rotate_key}",
    )
    return RedirectResponse(f"/clients/{client_id}/deployment", status_code=303)


@router.get("/clients/{client_id}/deployment", response_class=HTMLResponse)
def deployment_command_page(request: Request, client_id: int):
    require_user(request, admin=True)
    with db() as connection:
        client = connection.execute("SELECT * FROM clients WHERE id=? AND active=1", (client_id,)).fetchone()
        token = connection.execute(
            "SELECT * FROM deployment_tokens WHERE client_id=? AND used_at IS NULL AND expires_at>=? "
            "AND token_ciphertext IS NOT NULL ORDER BY created_at DESC LIMIT 1",
            (client_id, now_ts()),
        ).fetchone()
    if not client:
        raise HTTPException(404)
    command = ""
    expires_at = ""
    rotate_key = False
    if token:
        command = build_deployment_command(decrypt_deployment_token(token["token_ciphertext"]))
        expires_at = datetime.fromtimestamp(token["expires_at"], timezone.utc).astimezone().strftime("%d.%m.%Y %H:%M:%S %Z")
        rotate_key = bool(token["rotate_ssh_key"])
        audit(request, "deployment_token.view", client["slug"], f"expires_at={expires_at}")
    return render(
        request,
        "token_created.html",
        {
            "client": dict(client),
            "command": command,
            "minutes": int(application_settings()["deployment_token_minutes"]),
            "expires_at": expires_at,
            "start_immediately": bool(client["run_initial_backup"]),
            "rotate_ssh_key": rotate_key,
            "already_deployed": client_already_deployed(client),
        },
    )


@router.post("/clients/{client_id}/deployment/revoke")
def revoke_deployment_token(request: Request, client_id: int, csrf_token: str = Form(...)):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    with db() as connection:
        client = connection.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not client:
            raise HTTPException(404)
        connection.execute(
            "UPDATE deployment_tokens SET used_at=? WHERE client_id=? AND used_at IS NULL",
            ("revoked:" + now_iso(), client_id),
        )
    audit(request, "deployment_token.revoke", client["slug"], user_id=user["id"])
    return RedirectResponse(f"/clients/{client_id}", status_code=303)
