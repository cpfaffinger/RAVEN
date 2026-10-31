"""Sessions, CSRF checks, the audit log and the login and passkey helpers."""

from __future__ import annotations

import hmac
import secrets
import sqlite3
import threading
import time
from typing import Any

from fastapi import HTTPException, Request

import webauthn as passkeys

from core import CONFIG, application_settings, db, now_iso, now_ts, token_hash


LOGIN_FAILURES: dict[str, list[float]] = {}

# Open passkey ceremonies, keyed by a random flow id the browser sends back.
# They live in memory only: a portal restart merely asks the user to try again.
PASSKEY_FLOWS: dict[str, dict[str, Any]] = {}
PASSKEY_FLOW_LOCK = threading.Lock()
PASSKEY_FLOW_SECONDS = 300
PASSKEY_LIMIT_PER_USER = 20


def audit(request: Request | None, action: str, target: str = "", details: str = "", user_id: int | None = None) -> None:
    if request and user_id is None:
        session = session_user(request)
        user_id = session["id"] if session else None
    with db() as connection:
        connection.execute(
            "INSERT INTO audit_log(user_id,action,target,details,ip,created_at) VALUES(?,?,?,?,?,?)",
            (user_id, action, target, details[:2000], request.client.host if request and request.client else "", now_iso()),
        )


def session_user(request: Request) -> sqlite3.Row | None:
    raw = request.cookies.get("backup_portal_session", "")
    if not raw:
        return None
    with db() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at < ?", (now_ts(),))
        return connection.execute(
            "SELECT u.*,s.csrf_token,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires_at>=? AND u.active=1",
            (token_hash(raw), now_ts()),
        ).fetchone()


def require_user(request: Request, admin: bool = False) -> sqlite3.Row:
    user = session_user(request)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    if admin and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administratorrechte erforderlich")
    return user


def verify_csrf(user: sqlite3.Row, supplied: str) -> None:
    if not supplied or not hmac.compare_digest(user["csrf_token"], supplied):
        raise HTTPException(status_code=403, detail="Ungueltiges CSRF-Token")


def start_session(request: Request, user: sqlite3.Row, response: Any) -> None:
    """Open a portal session for an authenticated user and set its cookie."""
    ip = request.client.host if request.client else "unknown"
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    expires = now_ts() + int(CONFIG["security"].get("session_hours", 12)) * 3600
    with db() as connection:
        connection.execute(
            "INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,ip,user_agent,created_at) VALUES(?,?,?,?,?,?,?)",
            (token_hash(raw), user["id"], csrf, expires, ip, request.headers.get("user-agent", "")[:500], now_iso()),
        )
    response.set_cookie("backup_portal_session", raw, secure=True, httponly=True, samesite="strict", max_age=expires-now_ts(), path="/")


def passkey_relying_party() -> tuple[str, str]:
    """Return the RP ID and the exact origin passkeys are bound to.

    The RP ID is the portal FQDN and the origin carries the HTTPS port as well,
    so a passkey works on this portal only, never on another domain.
    """
    settings = application_settings()
    return str(settings["fqdn"]), str(settings["public_base_url"]).rstrip("/")


def open_passkey_flow(purpose: str, user_id: int | None = None) -> tuple[str, bytes]:
    flow_id = secrets.token_urlsafe(24)
    challenge = secrets.token_bytes(32)
    now = time.time()
    with PASSKEY_FLOW_LOCK:
        for key in [key for key, flow in PASSKEY_FLOWS.items() if flow["expires"] < now]:
            del PASSKEY_FLOWS[key]
        if len(PASSKEY_FLOWS) > 1000:
            raise HTTPException(429, "Zu viele offene Passkey-Anfragen")
        PASSKEY_FLOWS[flow_id] = {
            "purpose": purpose, "user_id": user_id, "challenge": challenge, "expires": now + PASSKEY_FLOW_SECONDS,
        }
    return flow_id, challenge


def take_passkey_flow(flow_id: str, purpose: str, user_id: int | None = None) -> bytes:
    """Consume a ceremony exactly once; a replayed or foreign flow is refused."""
    with PASSKEY_FLOW_LOCK:
        flow = PASSKEY_FLOWS.pop(str(flow_id), None)
    if not flow or flow["expires"] < time.time() or flow["purpose"] != purpose or flow["user_id"] != user_id:
        raise HTTPException(400, "Passkey-Anfrage ist abgelaufen; bitte erneut versuchen")
    return flow["challenge"]


def passkey_user_handle(connection: sqlite3.Connection, user: sqlite3.Row) -> str:
    """Return the opaque handle authenticators store for a user, creating it once."""
    handle = connection.execute("SELECT webauthn_handle FROM users WHERE id=?", (user["id"],)).fetchone()[0]
    if not handle:
        handle = passkeys.b64url_encode(secrets.token_bytes(32))
        connection.execute("UPDATE users SET webauthn_handle=? WHERE id=?", (handle, user["id"]))
    return str(handle)


async def json_body(request: Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(400, "Ungueltiges JSON")
    if not isinstance(data, dict):
        raise HTTPException(400, "Ungueltiges JSON")
    return data


def verify_csrf_header(request: Request, user: sqlite3.Row) -> None:
    verify_csrf(user, request.headers.get("x-csrf-token", ""))
