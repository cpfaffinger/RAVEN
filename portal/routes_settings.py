"""Manual, SMTP and application settings, certificates and portal users."""

from __future__ import annotations

import copy
import os
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

import backup_schedule
from domain_config import resolve_domain_config

from core import (
    ACME_CONFIG, ACME_STATE_DIR, BASE_DIR, CONFIG, CONFIG_PATH, DB_PATH, HOST_RE, PORTAL_FQDN,
    PORTAL_USER_RE, acme_configuration, application_settings, db, encrypt_deployment_token,
    hash_password, normalized_email, notification_recipients, now_iso,
)
from auth import audit, require_user, verify_csrf
from rendering import render, validated_schedule
from system_status import certificate_details, read_acme_state, systemd_active


router = APIRouter()


@router.get("/manual", response_class=HTMLResponse)
def manual(request: Request):
    require_user(request)
    settings = application_settings()
    return render(
        request,
        "manual.html",
        {
            "portal_url": settings["public_base_url"],
            "portal_port": int(CONFIG["server"]["port"]),
            "ssh_host": settings["fqdn"],
            "ssh_port": int(settings["backup_ssh_port"]),
            "token_minutes": int(settings["deployment_token_minutes"]),
            "config_path": str(CONFIG_PATH),
            "database_path": str(DB_PATH),
        },
    )


@router.get("/settings/smtp", response_class=HTMLResponse)
def smtp_settings_page(request: Request):
    require_user(request, admin=True)
    with db() as connection:
        settings = connection.execute(
            "SELECT id,enabled,host,port,username,from_address,timeout_seconds,updated_at "
            "FROM smtp_settings WHERE id=1"
        ).fetchone()
        recipients = notification_recipients(connection)
    if not settings:
        raise HTTPException(503, "SMTP ist noch nicht initialisiert")
    data = dict(settings)
    return render(
        request,
        "smtp_settings.html",
        {
            "smtp": data,
            "recipients": recipients,
            "message": request.query_params.get("message", ""),
        },
    )


@router.post("/settings/smtp")
def smtp_settings_update(
    request: Request,
    csrf_token: str = Form(...),
    host: str = Form(...),
    port: int = Form(...),
    username: str = Form(""),
    password: str = Form(""),
    from_address: str = Form(...),
    timeout_seconds: int = Form(20),
    enabled: str | None = Form(None),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    host = host.strip()
    username = username.strip()
    try:
        from_address = normalized_email(from_address)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not host or not 1 <= port <= 65535 or not 5 <= timeout_seconds <= 120:
        raise HTTPException(400, "Ungueltiger SMTP-Host, Port oder Timeout")
    if not from_address:
        raise HTTPException(400, "SMTP-Absenderadresse ist erforderlich")
    with db() as connection:
        current = connection.execute("SELECT password_ciphertext FROM smtp_settings WHERE id=1").fetchone()
        if not current:
            raise HTTPException(503, "SMTP ist noch nicht initialisiert")
        password_ciphertext = current["password_ciphertext"]
        if password:
            password_ciphertext = encrypt_deployment_token(password)
        if username and not password_ciphertext:
            raise HTTPException(400, "Fuer SMTP-Authentifizierung ist ein Passwort erforderlich")
        connection.execute(
            "UPDATE smtp_settings SET enabled=?,host=?,port=?,username=?,password_ciphertext=?,from_address=?,"
            "timeout_seconds=?,updated_by=?,updated_at=? WHERE id=1",
            (
                bool(enabled), host, port, username, password_ciphertext, from_address,
                timeout_seconds, user["id"], now_iso(),
            ),
        )
        connection.execute(
            "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE active=1",
            (now_iso(),),
        )
    audit(request, "smtp.settings", host, f"port={port} enabled={bool(enabled)} transport=plain", user_id=user["id"])
    return RedirectResponse("/settings/smtp?message=SMTP-Konfiguration+gespeichert", status_code=303)


@router.get("/settings/application", response_class=HTMLResponse)
def application_settings_page(request: Request):
    require_user(request, admin=True)
    settings = application_settings()
    configured = application_settings(prefer_pending_domain=True)
    return render(
        request,
        "application_settings.html",
        {
            "settings": settings,
            "configured": configured,
            "interval_choices": backup_schedule.INTERVAL_CHOICES,
            "message": request.query_params.get("message", ""),
            "min_remote_free_gib": round(int(settings["min_remote_free_bytes"]) / 1024**3, 3),
            "database_split_gib": round(int(settings["database_split_threshold_bytes"]) / 1024**3, 3),
        },
    )


@router.post("/settings/application")
def application_settings_update(
    request: Request,
    csrf_token: str = Form(...),
    domain_tld: str = Form(...),
    domain_subdomain: str = Form(""),
    username_prefix: str = Form(...),
    backup_ssh_port: int = Form(...),
    remote_hostname: str = Form(...),
    deployment_token_minutes: int = Form(...),
    default_schedule_hour: int = Form(...),
    default_schedule_minute: int = Form(...),
    default_interval_hours: int = Form(...),
    min_remote_free_gib: float = Form(...),
    database_split_gib: float = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    domain_tld = domain_tld.strip().lower().strip(".")
    domain_subdomain = domain_subdomain.strip().lower().strip(".")
    username_prefix = username_prefix.strip()
    remote_hostname = remote_hostname.strip()
    candidate = copy.deepcopy(CONFIG)
    candidate["domain"] = {"tld": domain_tld, "subdomain": domain_subdomain}
    try:
        resolved = resolve_domain_config(candidate)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,15}", username_prefix):
        raise HTTPException(400, "Benutzerpräfix ist ungültig")
    if not HOST_RE.fullmatch(remote_hostname):
        raise HTTPException(400, "Remote-Hostname ist ungültig")
    if not 1 <= backup_ssh_port <= 65535:
        raise HTTPException(400, "SSH-Port ist ungültig")
    if not 5 <= deployment_token_minutes <= 1440:
        raise HTTPException(400, "Deployment-Token-Laufzeit muss zwischen 5 und 1440 Minuten liegen")
    default_schedule_hour, default_schedule_minute, default_interval_hours, _offset = validated_schedule(
        default_schedule_hour, default_schedule_minute, default_interval_hours
    )
    if not 0.25 <= min_remote_free_gib <= 1048576 or not 0.01 <= database_split_gib <= 1048576:
        raise HTTPException(400, "Größenlimits liegen außerhalb des erlaubten Bereichs")
    min_remote_free_bytes = int(min_remote_free_gib * 1024**3)
    database_split_threshold_bytes = int(database_split_gib * 1024**3)
    with db() as connection:
        current = connection.execute("SELECT * FROM portal_settings WHERE id=1").fetchone()
        if not current:
            raise HTTPException(503, "Portal-Konfiguration ist noch nicht initialisiert")
        domain_changed = (
            domain_tld != current["domain_tld"] or domain_subdomain != current["domain_subdomain"]
        )
        connection.execute(
            "UPDATE portal_settings SET pending_domain_tld=?,pending_domain_subdomain=?,"
            "domain_change_pending=?,username_prefix=?,backup_ssh_port=?,remote_hostname=?,"
            "deployment_token_minutes=?,default_schedule_hour=?,default_schedule_minute=?,"
            "default_interval_hours=?,min_remote_free_bytes=?,database_split_threshold_bytes=?,"
            "updated_by=?,updated_at=? WHERE id=1",
            (
                domain_tld if domain_changed else "", domain_subdomain if domain_changed else "",
                domain_changed, username_prefix, backup_ssh_port, remote_hostname,
                deployment_token_minutes, default_schedule_hour, default_schedule_minute,
                default_interval_hours, min_remote_free_bytes, database_split_threshold_bytes,
                user["id"], now_iso(),
            ),
        )
        connection.execute(
            "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE active=1",
            (now_iso(),),
        )
    audit(
        request, "portal.settings", resolved["fqdn"],
        f"domain_pending={domain_changed} ssh_port={backup_ssh_port} token_minutes={deployment_token_minutes}",
        user_id=user["id"],
    )
    message = (
        "Konfiguration gespeichert; Domainwechsel wird nach erfolgreicher Zertifikatsausstellung aktiviert"
        if domain_changed else "Portal-Konfiguration gespeichert"
    )
    return RedirectResponse(f"/settings/application?message={quote(message)}", status_code=303)


@router.get("/certificates", response_class=HTMLResponse)
def certificates_page(request: Request):
    require_user(request, admin=True)
    challenges_state = read_acme_state("challenges.json")
    challenges = list(reversed(challenges_state.get("challenges", [])))
    challenge_running = any(item.get("status") in {"creating_dns", "waiting_dns", "propagated"} for item in challenges)
    cloudflare_settings = acme_configuration()
    configured_portal = application_settings(prefer_pending_domain=True)
    acme_display = copy.deepcopy(ACME_CONFIG)
    acme_display["domain"] = configured_portal["fqdn"]
    acme_display["cloudflare"] = dict(acme_display.get("cloudflare", {}))
    acme_display["cloudflare"]["zone_name"] = configured_portal["domain_tld"]
    with db() as connection:
        cloudflare_test = connection.execute(
            "SELECT ct.*,u.username AS requested_by_name FROM cloudflare_test_runs ct "
            "LEFT JOIN users u ON u.id=ct.requested_by ORDER BY ct.id DESC LIMIT 1"
        ).fetchone()
    return render(
        request,
        "certificates.html",
        {
            "certificate": certificate_details(),
            "acme": acme_display,
            "cloudflare": cloudflare_settings,
            "cloudflare_test": dict(cloudflare_test) if cloudflare_test else {},
            "challenges": challenges,
            "job": read_acme_state("job.json"),
            "renewal_running": systemd_active("backup-portal-cert-renew.service"),
            "challenge_running": challenge_running,
            "timer_active": systemd_active("backup-portal-cert-renew.timer"),
            "message": request.query_params.get("message", ""),
        },
    )


@router.post("/certificates/cloudflare")
def cloudflare_credentials_update(
    request: Request,
    csrf_token: str = Form(...),
    api_token: str = Form(""),
    zone_id: str = Form(""),
    ttl: int = Form(60),
    remove_token: str | None = Form(None),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    if ACME_CONFIG.get("mode") != "dns-cloudflare":
        raise HTTPException(400, "Cloudflare-DNS ist nicht aktiviert")
    if systemd_active("backup-portal-cert-renew.service"):
        raise HTTPException(409, "Cloudflare-Zugangsdaten koennen waehrend einer Zertifikatsanforderung nicht geaendert werden")
    zone_id = zone_id.strip()
    if zone_id and not re.fullmatch(r"[A-Fa-f0-9]{32}", zone_id):
        raise HTTPException(400, "Cloudflare Zone-ID muss leer oder 32 Hex-Zeichen lang sein")
    if ttl != 1 and not 60 <= ttl <= 86400:
        raise HTTPException(400, "Cloudflare TTL muss 1 oder 60 bis 86400 Sekunden sein")
    api_token = api_token.strip()
    if api_token and not re.fullmatch(r"[A-Za-z0-9_-]{20,512}", api_token):
        raise HTTPException(400, "Cloudflare API-Token hat ein ungueltiges Format")
    with db() as connection:
        current = connection.execute(
            "SELECT cloudflare_token_ciphertext FROM acme_settings WHERE id=1"
        ).fetchone()
        if not current:
            raise HTTPException(503, "ACME-Einstellungen sind noch nicht initialisiert")
        token_ciphertext = current["cloudflare_token_ciphertext"]
        if remove_token:
            token_ciphertext = ""
        elif api_token:
            token_ciphertext = encrypt_deployment_token(api_token)
        connection.execute(
            "UPDATE acme_settings SET cloudflare_token_ciphertext=?,cloudflare_zone_id=?,cloudflare_ttl=?,"
            "updated_by=?,updated_at=? WHERE id=1",
            (token_ciphertext, zone_id, ttl, user["id"], now_iso()),
        )
    action = "removed" if remove_token else "updated"
    audit(request, "cloudflare.credentials", PORTAL_FQDN, f"{action} zone_id={'set' if zone_id else 'auto'} ttl={ttl}", user_id=user["id"])
    message = "Cloudflare-API-Token+entfernt" if remove_token else "Cloudflare-Einstellungen+gespeichert"
    return RedirectResponse(f"/certificates?message={message}", status_code=303)


@router.post("/certificates/cloudflare/test")
def cloudflare_credentials_test(request: Request, csrf_token: str = Form(...)):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    if ACME_CONFIG.get("mode") != "dns-cloudflare":
        raise HTTPException(400, "Cloudflare-DNS ist nicht aktiviert")
    if not acme_configuration().get("token_configured"):
        raise HTTPException(409, "Cloudflare API-Token ist nicht konfiguriert")
    started = time.monotonic()
    hook = Path(str(ACME_CONFIG.get("hook", BASE_DIR / "acme_dns_hook.py")))
    command = [sys.executable, str(hook), "cloudflare-check", "--config", str(CONFIG_PATH)]
    try:
        process = subprocess.run(
            command, capture_output=True, text=True, errors="replace", timeout=45, check=False,
        )
        output = (process.stdout + ("\n" if process.stdout and process.stderr else "") + process.stderr).strip()
        message = output[-1000:] or f"Cloudflare-Test endete mit Status {process.returncode}"
        status = "success" if process.returncode == 0 else "failure"
    except (OSError, subprocess.TimeoutExpired) as exc:
        status = "failure"
        message = f"{type(exc).__name__}: {exc}"
    duration_ms = int((time.monotonic() - started) * 1000)
    with db() as connection:
        connection.execute(
            "INSERT INTO cloudflare_test_runs(status,requested_by,tested_at,duration_ms,message) VALUES(?,?,?,?,?)",
            (status, user["id"], now_iso(), duration_ms, message),
        )
        connection.execute(
            "DELETE FROM cloudflare_test_runs WHERE id IN "
            "(SELECT id FROM cloudflare_test_runs ORDER BY id DESC LIMIT -1 OFFSET 100)"
        )
    audit(request, "cloudflare.test", application_settings(prefer_pending_domain=True)["fqdn"], status, user_id=user["id"])
    return RedirectResponse(
        f"/certificates?message={quote('Cloudflare-Test erfolgreich' if status == 'success' else 'Cloudflare-Test fehlgeschlagen')}",
        status_code=303,
    )


@router.post("/certificates/request")
def certificate_request(request: Request, csrf_token: str = Form(...)):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    if ACME_CONFIG.get("mode") not in {"dns-manual", "dns-cloudflare"}:
        raise HTTPException(400, "DNS-01-Verwaltung ist nicht aktiviert")
    ACME_STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ACME_STATE_DIR, 0o700)
    marker = ACME_STATE_DIR / "force-request"
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(now_iso() + "\n")
    process = subprocess.run(
        ["/usr/bin/systemctl", "start", "--no-block", "backup-portal-cert-renew.service"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if process.returncode != 0:
        try:
            marker.unlink()
        except FileNotFoundError:
            pass
        raise HTTPException(500, (process.stderr or process.stdout or "Erneuerungsdienst konnte nicht gestartet werden")[:500])
    audit(request, "certificate.request", str(ACME_CONFIG.get("domain", "")), "force=true", user_id=user["id"])
    return RedirectResponse("/certificates?message=Anforderung+gestartet", status_code=303)


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    require_user(request, admin=True)
    with db() as connection:
        users = connection.execute(
            "SELECT id,username,display_name,role,email,receive_notifications,active,created_at "
            "FROM users ORDER BY username"
        ).fetchall()
    return render(
        request,
        "users.html",
        {"users": users, "error": "", "message": request.query_params.get("message", "")},
    )


@router.post("/users", response_class=HTMLResponse)
def user_create(
    request: Request,
    username: str = Form(...),
    display_name: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    email: str = Form(""),
    receive_notifications: str | None = Form(None),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    username = username.strip()
    if not PORTAL_USER_RE.fullmatch(username) or role not in {"admin", "viewer"}:
        raise HTTPException(400, "Invalid user data")
    try:
        email = normalized_email(email)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if receive_notifications and not email:
        raise HTTPException(400, "Fuer Mailbenachrichtigungen ist eine E-Mail-Adresse erforderlich")
    try:
        encoded = hash_password(password)
        with db() as connection:
            connection.execute(
                "INSERT INTO users(username,display_name,password_hash,role,email,receive_notifications,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    username, display_name.strip() or username, encoded, role, email,
                    bool(receive_notifications), now_iso(),
                ),
            )
            if receive_notifications:
                connection.execute(
                    "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? "
                    "WHERE active=1",
                    (now_iso(),),
                )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "User already exists")
    audit(request, "user.create", username, f"role={role}")
    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/notifications")
def user_notifications_update(
    request: Request,
    user_id: int,
    email: str = Form(""),
    receive_notifications: str | None = Form(None),
    csrf_token: str = Form(...),
):
    actor = require_user(request, admin=True)
    verify_csrf(actor, csrf_token)
    try:
        email = normalized_email(email)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if receive_notifications and not email:
        raise HTTPException(400, "Fuer Mailbenachrichtigungen ist eine E-Mail-Adresse erforderlich")
    with db() as connection:
        target = connection.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404)
        connection.execute(
            "UPDATE users SET email=?,receive_notifications=? WHERE id=?",
            (email, bool(receive_notifications), user_id),
        )
        connection.execute(
            "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? "
            "WHERE active=1",
            (now_iso(),),
        )
    audit(
        request,
        "user.notifications",
        target["username"],
        f"email_set={bool(email)} enabled={bool(receive_notifications)}",
        user_id=actor["id"],
    )
    return RedirectResponse(
        f"/users?message={quote('Benachrichtigungseinstellungen gespeichert')}", status_code=303
    )


@router.post("/users/{user_id}/toggle")
def user_toggle(request: Request, user_id: int, csrf_token: str = Form(...)):
    actor = require_user(request, admin=True)
    verify_csrf(actor, csrf_token)
    if actor["id"] == user_id:
        raise HTTPException(400, "Eigenes Konto kann nicht deaktiviert werden")
    with db() as connection:
        target = connection.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404)
        if target["active"] and target["role"] == "admin":
            admins = connection.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
            if admins <= 1:
                raise HTTPException(400, "Letzter Administrator kann nicht deaktiviert werden")
        connection.execute("UPDATE users SET active=? WHERE id=?", (0 if target["active"] else 1, user_id))
        connection.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        connection.execute(
            "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? "
            "WHERE active=1",
            (now_iso(),),
        )
    audit(request, "user.toggle", target["username"], f"active={not bool(target['active'])}")
    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/password")
def user_password(request: Request, user_id: int, password: str = Form(...), csrf_token: str = Form(...)):
    actor = require_user(request, admin=True)
    verify_csrf(actor, csrf_token)
    encoded = hash_password(password)
    with db() as connection:
        target = connection.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404)
        connection.execute("UPDATE users SET password_hash=? WHERE id=?", (encoded, user_id))
        connection.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    audit(request, "user.password_reset", target["username"])
    return RedirectResponse("/users", status_code=303)
