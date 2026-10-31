"""The API the agents and the bootstrap script talk to."""

from __future__ import annotations

import base64
import json
import os
import pwd
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from core import (
    CONFIG, HOST_RE, LOG, PUBLIC_KEY_RE, agent_script_asset, application_settings,
    client_already_deployed, db, now_iso, now_ts, smtp_configuration, token_hash,
)
from auth import audit
from workers import client_schedule_state, close_dead_run, policy_payload


router = APIRouter()


def agent_script_update(reported_sha256: str) -> dict[str, Any] | None:
    """Return the current agent script when the source server runs a different one."""
    try:
        digest, content = agent_script_asset()
    except OSError:
        LOG.exception("Agent-Skript konnte fuer die Auslieferung nicht gelesen werden")
        return None
    if not reported_sha256 or reported_sha256 == digest:
        return None
    return {"sha256": digest, "content_b64": base64.b64encode(content).decode("ascii")}


def bearer(request: Request) -> str:
    value = request.headers.get("authorization", "")
    if not value.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    return value[7:].strip()


def deployment_for_token(raw: str) -> tuple[sqlite3.Row, sqlite3.Row]:
    with db() as connection:
        token = connection.execute(
            "SELECT * FROM deployment_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>=?",
            (token_hash(raw), now_ts()),
        ).fetchone()
        if not token:
            raise HTTPException(401, "Deployment token invalid or expired")
        client = connection.execute("SELECT * FROM clients WHERE id=? AND active=1", (token["client_id"],)).fetchone()
    if not client:
        raise HTTPException(404)
    return token, client


@router.get("/bootstrap", response_class=PlainTextResponse)
def bootstrap(request: Request):
    raw = bearer(request)
    token, client = deployment_for_token(raw)
    source = Path(CONFIG["paths"]["bootstrap_script"]).read_text(encoding="utf-8")
    prefix = (
        f"PORTAL_URL = {str(application_settings()['public_base_url']).rstrip('/')!r}\n"
        f"DEPLOYMENT_TOKEN = {raw!r}\nCLIENT_SLUG = {client['slug']!r}\n"
        f"ROTATE_SSH_KEY = {bool(token['rotate_ssh_key'])!r}\n"
    )
    return PlainTextResponse(prefix + source, headers={"Content-Disposition": "inline", "X-Content-Type-Options": "nosniff"})


def validate_public_key(value: str) -> str:
    value = value.strip()
    match = PUBLIC_KEY_RE.fullmatch(value)
    if not match:
        raise HTTPException(400, "Only ssh-ed25519 public keys are accepted")
    try:
        decoded = base64.b64decode(match.group(1), validate=True)
    except Exception:
        raise HTTPException(400, "Invalid SSH key encoding")
    if len(decoded) < 40 or len(decoded) > 128:
        raise HTTPException(400, "Invalid SSH key length")
    return "ssh-ed25519 " + match.group(1)


def build_agent_config(client: sqlite3.Row, source_hostname: str, has_mariadb: bool, agent_token: str) -> str:
    onboarding = application_settings()
    smtp = smtp_configuration()
    alias = f"raven-backup-{client['slug']}"
    with db() as connection:
        policy = policy_payload(connection, client["policy_id"])
    path_config = "\n".join(
        "[[backup_paths]]\n"
        f"source_path = {json.dumps(item['source_path'])}\n"
        f"target_name = {json.dumps(item['target_name'])}\n"
        f"mode = {json.dumps(item['mode'])}\n"
        for item in policy["paths"]
    )
    empty_sources_config = "sources = []\n" if not policy["paths"] else ""
    to_addresses = json.dumps(list(smtp["to"]))
    portal_url = str(onboarding["public_base_url"]).rstrip('/')
    mariadb_databases = has_mariadb and policy["mariadb_databases_enabled"]
    mariadb_users = has_mariadb and policy["mariadb_users_enabled"]
    mail_on_success = bool(policy["mail_on_success"]) and bool(smtp["enabled"])
    mail_on_failure = bool(policy["mail_on_failure"]) and bool(smtp["enabled"])
    mail_on_skipped = bool(policy["mail_on_skipped"]) and bool(smtp["enabled"])
    return f'''[backup]\nssh_target = "{alias}"\nexpected_source_hostname = "{source_hostname}"\nexpected_ssh_hostname = "{onboarding['fqdn']}"\nexpected_ssh_user = "{client['username']}"\nexpected_ssh_port = {int(onboarding['backup_ssh_port'])}\nexpected_remote_hostname = "{onboarding['remote_hostname']}"\nexpected_remote_home = "{client['home_path']}"\npolicy_id = {int(policy['id'])}\npolicy_name = {json.dumps(policy['name'])}\nconfig_version = {int(client['agent_config_version'])}\nmariadb_available = {str(has_mariadb).lower()}\nmariadb_enabled = {str(mariadb_databases or mariadb_users).lower()}\nmariadb_databases_enabled = {str(mariadb_databases).lower()}\nmariadb_users_enabled = {str(mariadb_users).lower()}\npostgresql_databases_enabled = {str(bool(policy['postgresql_databases_enabled'])).lower()}\npostgresql_roles_enabled = {str(bool(policy['postgresql_roles_enabled'])).lower()}\nmin_remote_free_bytes = {int(onboarding['min_remote_free_bytes'])}\ndatabase_split_threshold_bytes = {int(onboarding['database_split_threshold_bytes'])}\nstream_attempts = 2\nrsync_attempts = 3\nzstd_level = 3\nssh_control_path = "/run/raven-backup-ssh-%C"\nlocal_lock_path = "/run/raven-backup-agent-{client['slug']}.lock"\nstate_path = "/var/lib/raven-backup/agent-{client['slug']}.json"\n{empty_sources_config}\n{path_config}\n[schedule]\nhour = {int(policy['schedule_hour'])}\nminute = {int(policy['schedule_minute'])}\ninterval_hours = {int(policy['interval_hours'])}\n\n[notifications]\nmail_on_success = {str(mail_on_success).lower()}\nmail_on_failure = {str(mail_on_failure).lower()}\nmail_on_skipped = {str(mail_on_skipped).lower()}\n\n[logging]\nlevel = {json.dumps(client['agent_log_level'])}\nlocal_enabled = {str(bool(client['agent_log_local'])).lower()}\nportal_enabled = {str(bool(client['agent_log_portal'])).lower()}\ninclude_traceback = {str(bool(client['agent_log_traceback'])).lower()}\nportal_max_bytes = {int(client['agent_log_max_bytes'])}\n\n[status]\nenabled = true\nendpoint = "{portal_url}/api/agent/status"\npoll_endpoint = "{portal_url}/api/agent/poll"\ncommand_endpoint = "{portal_url}/api/agent/commands"\nlog_endpoint = "{portal_url}/api/agent/logs"\ntoken = "{agent_token}"\ntimeout_seconds = 15\n\n[smtp]\nhost = "{smtp['host']}"\nport = {int(smtp['port'])}\nusername = {json.dumps(smtp['username'])}\npassword = {json.dumps(smtp['password'])}\nfrom_address = {json.dumps(smtp['from_address'])}\nto = {to_addresses}\nstarttls = false\ntimeout_seconds = {int(smtp.get('timeout_seconds', 20))}\n'''


@router.post("/api/onboard/register")
async def onboard_register(request: Request):
    raw = bearer(request)
    token, client = deployment_for_token(raw)
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    public_key = validate_public_key(str(payload.get("public_key", "")))
    source_hostname = str(payload.get("source_hostname", "")).strip()
    if not HOST_RE.fullmatch(source_hostname):
        raise HTTPException(400, "Invalid source hostname")
    has_mariadb = bool(payload.get("has_mariadb", False))
    settings = application_settings()
    account = pwd.getpwnam(client["username"])
    home = Path(account.pw_dir)
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    authorized = ssh_dir / "authorized_keys"
    lines = authorized.read_text(encoding="utf-8").splitlines() if authorized.exists() else []
    marker = f"raven-client:{client['id']}"
    lines = [line for line in lines if marker not in line]
    lines.append(f"restrict {public_key} {marker}")
    authorized.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chown(authorized, account.pw_uid, account.pw_gid)
    os.chmod(authorized, 0o600)
    agent_token = secrets.token_urlsafe(32)
    script_sha256, backup_script = agent_script_asset()
    with db() as connection:
        connection.execute(
            "UPDATE clients SET source_hostname=?,agent_token_hash=?,mariadb_available=?,"
            "agent_script_sha256=?,last_event='onboarded',last_event_at=? WHERE id=?",
            (source_hostname, token_hash(agent_token), has_mariadb, script_sha256, now_iso(), client["id"]),
        )
        connection.execute("UPDATE deployment_tokens SET used_at=? WHERE token_hash=?", (now_iso(), token["token_hash"]))
    host_key = Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text(encoding="utf-8").split()
    known_hosts_line = f"[{settings['fqdn']}]:{int(settings['backup_ssh_port'])} {host_key[0]} {host_key[1]}"
    alias = f"raven-backup-{client['slug']}"
    ssh_config = f"Host {alias}\n    HostName {settings['fqdn']}\n    Port {int(settings['backup_ssh_port'])}\n    User {client['username']}\n    IdentityFile /root/.ssh/raven_backup_{client['slug']}\n    IdentitiesOnly yes\n    Compression yes\n    BatchMode yes\n    StrictHostKeyChecking yes\n"
    backup_config = build_agent_config(client, source_hostname, has_mariadb, agent_token).encode("utf-8")
    cron_line = "* * * * * /usr/bin/python3 -u /root/backup --config /root/backup-job.toml --poll >> /var/log/raven-backup.log 2>&1"
    audit(
        request,
        "client.onboard",
        client["slug"],
        f"source={source_hostname} redeploy={client_already_deployed(client)} "
        f"rotate_ssh_key={bool(token['rotate_ssh_key'])}",
    )
    return JSONResponse(
        {
            "backup_script_b64": base64.b64encode(backup_script).decode(),
            "backup_config_b64": base64.b64encode(backup_config).decode(),
            "ssh_config": ssh_config,
            "known_hosts_line": known_hosts_line,
            "cron_line": cron_line,
            "run_initial_backup": bool(client["run_initial_backup"]),
        }
    )


def authenticated_agent(request: Request) -> sqlite3.Row:
    raw = bearer(request)
    with db() as connection:
        client = connection.execute("SELECT * FROM clients WHERE agent_token_hash=? AND active=1", (token_hash(raw),)).fetchone()
    if not client:
        raise HTTPException(401, "Invalid agent token")
    return client


@router.post("/api/agent/poll")
async def agent_poll(request: Request):
    raw_agent_token = bearer(request)
    client = authenticated_agent(request)
    try:
        data = await request.json()
    except Exception:
        data = {}
    reported_hostname = str(data.get("hostname", "")).strip()
    if reported_hostname and client["source_hostname"] and reported_hostname != client["source_hostname"]:
        # Remember what the agent reports so an admin can accept a renamed
        # server in the portal instead of onboarding it again.
        if HOST_RE.fullmatch(reported_hostname):
            with db() as connection:
                connection.execute(
                    "UPDATE clients SET reported_hostname=?,reported_hostname_at=? WHERE id=?",
                    (reported_hostname, now_iso(), client["id"]),
                )
        raise HTTPException(409, "Source hostname mismatch")
    try:
        reported_config_version = int(data.get("config_version", 0))
    except (TypeError, ValueError):
        reported_config_version = 0
    reported_mariadb = bool(data.get("mariadb_available", client["mariadb_available"]))
    reported_script_sha256 = str(data.get("script_sha256", "")).strip().lower()
    if reported_script_sha256 and not re.fullmatch(r"[0-9a-f]{64}", reported_script_sha256):
        raise HTTPException(400, "Invalid agent script digest")
    claimed_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE clients SET last_poll_at=?,mariadb_available=?,agent_script_sha256=?,"
            "reported_hostname=NULL,reported_hostname_at=NULL WHERE id=?",
            (now_iso(), reported_mariadb, reported_script_sha256, client["id"]),
        )
        # The agent polls only while it holds its run lock, so nothing of this
        # host can still be running when a poll arrives.
        close_dead_run(connection, client["id"], "Agent hat den Lauf ohne Abschlussmeldung beendet")
        connection.execute(
            "UPDATE backup_commands SET status='queued',claimed_at=NULL,message='Claim timeout; erneut freigegeben' "
            "WHERE client_id=? AND status='claimed' AND claimed_at<?",
            (client["id"], claimed_cutoff),
        )
        cleanup_active = connection.execute(
            "SELECT 1 FROM policy_cleanup_runs WHERE policy_id=? AND status IN ('queued','running')",
            (client["policy_id"],),
        ).fetchone()
        command = None if cleanup_active else connection.execute(
            "SELECT * FROM backup_commands WHERE client_id=? AND status='queued' ORDER BY id LIMIT 1",
            (client["id"],),
        ).fetchone()
        if command:
            connection.execute(
                "UPDATE backup_commands SET status='claimed',claimed_at=? WHERE id=? AND status='queued'",
                (now_iso(), command["id"]),
            )
        client = connection.execute("SELECT * FROM clients WHERE id=?", (client["id"],)).fetchone()
        schedule_state = client_schedule_state(connection, client)
    # The schedule travels with every poll so a policy change reaches the agent
    # on its next request, without waiting for a configuration rewrite.
    response: dict[str, Any] = {
        "action": "none",
        "server_time": now_iso(),
        "schedule": schedule_state,
    }
    if command:
        response.update({
            "action": "backup",
            "command_id": command["id"],
            "reason": command["reason"],
            "force": bool(command["force"]),
            "due_at": command["due_at"],
            "requested_at": command["requested_at"],
            "policy": json.loads(command["policy_snapshot"]) if command["policy_snapshot"] else None,
        })
    script_update = agent_script_update(reported_script_sha256)
    if script_update:
        response["script_update"] = script_update
    if reported_config_version != int(client["agent_config_version"]):
        refreshed_config = build_agent_config(
            client,
            str(client["source_hostname"] or reported_hostname),
            bool(client["mariadb_available"]),
            raw_agent_token,
        ).encode("utf-8")
        response["config_update"] = {
            "version": int(client["agent_config_version"]),
            "content_b64": base64.b64encode(refreshed_config).decode("ascii"),
        }
    return JSONResponse(response)


@router.post("/api/agent/commands/{command_id}")
async def agent_command_state(request: Request, command_id: int):
    client = authenticated_agent(request)
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    status = str(data.get("status", ""))
    if status not in {"running", "success", "failure", "skipped"}:
        raise HTTPException(400, "Invalid command status")
    run_id = str(data.get("run_id", ""))[:64] or None
    message = str(data.get("message", ""))[:2000] or None
    with db() as connection:
        command = connection.execute(
            "SELECT * FROM backup_commands WHERE id=? AND client_id=?",
            (command_id, client["id"]),
        ).fetchone()
        if not command:
            raise HTTPException(404, "Command not found")
        if status == "running":
            connection.execute(
                "UPDATE backup_commands SET status='running',started_at=?,run_id=?,message=? WHERE id=?",
                (now_iso(), run_id, message, command_id),
            )
        else:
            connection.execute(
                "UPDATE backup_commands SET status=?,finished_at=?,run_id=COALESCE(?,run_id),message=? WHERE id=?",
                (status, now_iso(), run_id, message, command_id),
            )
    return JSONResponse({"status": "accepted"})


@router.post("/api/agent/status")
async def agent_status(request: Request):
    client = authenticated_agent(request)
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    event = str(data.get("event", ""))
    if event not in {"heartbeat", "started", "success", "failure"}:
        raise HTTPException(400, "Invalid event")
    payload = data.get("payload", {})
    serialized = json.dumps(payload, ensure_ascii=False)[:500_000]
    run_id = payload.get("run_id") if isinstance(payload, dict) else None
    command_id = payload.get("command_id") if isinstance(payload, dict) else None
    try:
        command_id = int(command_id) if command_id is not None else None
    except (TypeError, ValueError):
        command_id = None
    with db() as connection:
        connection.execute(
            "INSERT INTO status_events(client_id,event,run_id,payload,created_at) VALUES(?,?,?,?,?)",
            (client["id"], event, run_id, serialized, now_iso()),
        )
        connection.execute(
            "UPDATE clients SET last_event=?,last_event_at=?,last_payload=?,"
            "last_success_at=CASE WHEN ?='success' THEN ? ELSE last_success_at END WHERE id=?",
            (event, now_iso(), serialized, event, now_iso(), client["id"]),
        )
        if command_id and event in {"started", "success", "failure"}:
            command_status = "running" if event == "started" else event
            connection.execute(
                "UPDATE backup_commands SET status=?,run_id=COALESCE(?,run_id),"
                "started_at=CASE WHEN ?='running' THEN COALESCE(started_at,?) ELSE started_at END,"
                "finished_at=CASE WHEN ? IN ('success','failure') THEN ? ELSE finished_at END "
                "WHERE id=? AND client_id=?",
                (
                    command_status,
                    run_id,
                    command_status,
                    now_iso(),
                    command_status,
                    now_iso(),
                    command_id,
                    client["id"],
                ),
            )
    return JSONResponse({"status": "accepted"})


def redact_agent_log(value: str) -> str:
    value = re.sub(r"(?i)(authorization\s*:\s*bearer|bearer)\s+[^\s]+", r"\1 [REDACTED]", value)
    value = re.sub(r"(?i)\b(password|passwd|token|secret)\s*([=:])\s*[^\s]+", r"\1\2[REDACTED]", value)
    return value


@router.post("/api/agent/logs")
async def agent_log_upload(request: Request):
    client = authenticated_agent(request)
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    upload_id = str(data.get("upload_id", "")).strip()
    status = str(data.get("status", "")).strip()
    source_hostname = str(data.get("source_hostname", "")).strip()
    if not re.fullmatch(r"[A-Fa-f0-9-]{16,64}", upload_id):
        raise HTTPException(400, "Invalid upload id")
    if status not in {"success", "failure", "test"}:
        raise HTTPException(400, "Invalid log status")
    if not HOST_RE.fullmatch(source_hostname):
        raise HTTPException(400, "Invalid source hostname")
    if client["source_hostname"] and source_hostname != client["source_hostname"]:
        raise HTTPException(409, "Source hostname mismatch")
    log_text = redact_agent_log(str(data.get("log_text", "")))
    encoded_log = log_text.encode("utf-8", "replace")
    if len(encoded_log) > 524_288:
        raise HTTPException(413, "Agent log too large")
    log_level = str(data.get("log_level", "INFO")).upper()
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise HTTPException(400, "Invalid log level")
    command_id = data.get("command_id")
    try:
        command_id = int(command_id) if command_id is not None else None
    except (TypeError, ValueError):
        raise HTTPException(400, "Invalid command id")
    report = data.get("report", {})
    if not isinstance(report, dict):
        raise HTTPException(400, "Invalid report")
    report_json = json.dumps(report, ensure_ascii=False)
    if len(report_json.encode("utf-8")) > 300_000:
        raise HTTPException(413, "Agent report too large")
    with db() as connection:
        if command_id and not connection.execute(
            "SELECT 1 FROM backup_commands WHERE id=? AND client_id=?", (command_id, client["id"])
        ).fetchone():
            raise HTTPException(400, "Command does not belong to client")
        connection.execute(
            "INSERT INTO backup_run_logs(client_id,command_id,upload_id,run_id,status,source_hostname,phase,"
            "started_at,finished_at,log_level,log_text,log_bytes,truncated,report_json,received_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(client_id,upload_id) DO UPDATE SET command_id=excluded.command_id,run_id=excluded.run_id,"
            "status=excluded.status,phase=excluded.phase,finished_at=excluded.finished_at,log_level=excluded.log_level,"
            "log_text=excluded.log_text,log_bytes=excluded.log_bytes,truncated=excluded.truncated,"
            "report_json=excluded.report_json,received_at=excluded.received_at",
            (
                client["id"], command_id, upload_id, str(data.get("run_id", ""))[:64] or None,
                status, source_hostname, str(data.get("phase", ""))[:64] or None,
                str(data.get("started_at", ""))[:64] or None, str(data.get("finished_at", ""))[:64] or now_iso(),
                log_level, log_text, len(encoded_log), bool(data.get("truncated", False)), report_json, now_iso(),
            ),
        )
    return JSONResponse({"status": "stored"})
