"""Login, logout, the account page and passkey registration."""

from __future__ import annotations

import sqlite3
import time
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

import webauthn as passkeys

from core import db, now_iso, token_hash, verify_password
from auth import (
    LOGIN_FAILURES, PASSKEY_FLOW_SECONDS, PASSKEY_LIMIT_PER_USER, audit, json_body,
    open_passkey_flow, passkey_relying_party, passkey_user_handle, require_user, session_user,
    start_session, take_passkey_flow, verify_csrf, verify_csrf_header,
)
from rendering import render


router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if session_user(request):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", {"error": ""})


@router.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else "unknown"
    recent = [stamp for stamp in LOGIN_FAILURES.get(ip, []) if time.time() - stamp < 900]
    LOGIN_FAILURES[ip] = recent
    if len(recent) >= 8:
        audit(request, "login.rate_limited", username)
        return render(request, "login.html", {"error": "Zu viele Versuche. Bitte spaeter erneut versuchen."}, 429)
    with db() as connection:
        user = connection.execute("SELECT * FROM users WHERE username=? AND active=1", (username.strip(),)).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        LOGIN_FAILURES[ip].append(time.time())
        audit(request, "login.failed", username)
        time.sleep(0.4)
        return render(request, "login.html", {"error": "Benutzername oder Passwort ist falsch."}, 401)
    LOGIN_FAILURES.pop(ip, None)
    audit(request, "login.success", username, user_id=user["id"])
    response = RedirectResponse("/", status_code=303)
    start_session(request, user, response)
    return response


@router.post("/login/passkey/options")
def login_passkey_options(request: Request):
    """Start a passwordless login with any passkey registered for this portal."""
    rp_id, _origin = passkey_relying_party()
    flow_id, challenge = open_passkey_flow("login")
    return JSONResponse({
        "flow": flow_id,
        "publicKey": {
            "challenge": passkeys.b64url_encode(challenge),
            "rpId": rp_id,
            "timeout": PASSKEY_FLOW_SECONDS * 1000,
            "userVerification": "required",
            "allowCredentials": [],
        },
    })


@router.post("/login/passkey")
async def login_passkey(request: Request):
    ip = request.client.host if request.client else "unknown"
    recent = [stamp for stamp in LOGIN_FAILURES.get(ip, []) if time.time() - stamp < 900]
    LOGIN_FAILURES[ip] = recent
    if len(recent) >= 8:
        audit(request, "login.rate_limited", "passkey")
        return JSONResponse({"error": "Zu viele Versuche. Bitte spaeter erneut versuchen."}, status_code=429)
    data = await json_body(request)
    challenge = take_passkey_flow(str(data.get("flow", "")), "login")
    rp_id, origin = passkey_relying_party()
    credential_id = str(data.get("id", ""))
    with db() as connection:
        stored = connection.execute(
            "SELECT c.*,u.username,u.webauthn_handle FROM webauthn_credentials c JOIN users u ON u.id=c.user_id "
            "WHERE c.credential_id=? AND u.active=1",
            (credential_id,),
        ).fetchone()
    try:
        if not stored:
            raise passkeys.WebAuthnError("Dieser Passkey ist im Portal nicht registriert")
        user_handle = str(data.get("userHandle") or "")
        if user_handle and user_handle != stored["webauthn_handle"]:
            raise passkeys.WebAuthnError("Passkey gehoert zu einem anderen Benutzer")
        sign_count = passkeys.verify_authentication(
            client_data_json=passkeys.b64url_decode(str(data.get("clientDataJSON", ""))),
            authenticator_data=passkeys.b64url_decode(str(data.get("authenticatorData", ""))),
            signature=passkeys.b64url_decode(str(data.get("signature", ""))),
            challenge=challenge, origin=origin, rp_id=rp_id,
            public_key=bytes(stored["public_key"]), algorithm=int(stored["algorithm"]),
            stored_sign_count=int(stored["sign_count"]),
        )
    except passkeys.WebAuthnError as exc:
        LOGIN_FAILURES[ip].append(time.time())
        audit(request, "login.passkey_failed", stored["username"] if stored else credential_id[:64], str(exc))
        time.sleep(0.4)
        return JSONResponse({"error": f"Anmeldung mit Passkey fehlgeschlagen: {exc}"}, status_code=401)
    LOGIN_FAILURES.pop(ip, None)
    with db() as connection:
        connection.execute(
            "UPDATE webauthn_credentials SET sign_count=?,last_used_at=? WHERE id=?",
            (sign_count, now_iso(), stored["id"]),
        )
        user = connection.execute("SELECT * FROM users WHERE id=? AND active=1", (stored["user_id"],)).fetchone()
    if not user:
        return JSONResponse({"error": "Benutzer ist deaktiviert"}, status_code=401)
    audit(request, "login.success", user["username"], f"passkey={stored['name']}", user_id=user["id"])
    response = JSONResponse({"redirect": "/"})
    start_session(request, user, response)
    return response


@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request):
    user = require_user(request)
    with db() as connection:
        credentials = connection.execute(
            "SELECT id,name,created_at,last_used_at FROM webauthn_credentials WHERE user_id=? ORDER BY id",
            (user["id"],),
        ).fetchall()
    return render(request, "account.html", {
        "credentials": credentials,
        "message": request.query_params.get("message", ""),
    })


@router.post("/account/passkeys/options")
def passkey_register_options(request: Request):
    user = require_user(request)
    verify_csrf_header(request, user)
    rp_id, _origin = passkey_relying_party()
    with db() as connection:
        handle = passkey_user_handle(connection, user)
        existing = connection.execute(
            "SELECT credential_id FROM webauthn_credentials WHERE user_id=?", (user["id"],)
        ).fetchall()
    if len(existing) >= PASSKEY_LIMIT_PER_USER:
        raise HTTPException(409, f"Hoechstens {PASSKEY_LIMIT_PER_USER} Passkeys je Benutzer")
    flow_id, challenge = open_passkey_flow("register", int(user["id"]))
    return JSONResponse({
        "flow": flow_id,
        "publicKey": {
            "challenge": passkeys.b64url_encode(challenge),
            "rp": {"id": rp_id, "name": "RAVEN"},
            "user": {"id": handle, "name": user["username"], "displayName": user["display_name"] or user["username"]},
            "pubKeyCredParams": [{"type": "public-key", "alg": alg} for alg in passkeys.SUPPORTED_ALGORITHMS],
            "timeout": PASSKEY_FLOW_SECONDS * 1000,
            "attestation": "none",
            "authenticatorSelection": {"residentKey": "required", "userVerification": "required"},
            "excludeCredentials": [{"type": "public-key", "id": row["credential_id"]} for row in existing],
        },
    })


@router.post("/account/passkeys")
async def passkey_register(request: Request):
    user = require_user(request)
    verify_csrf_header(request, user)
    data = await json_body(request)
    challenge = take_passkey_flow(str(data.get("flow", "")), "register", int(user["id"]))
    rp_id, origin = passkey_relying_party()
    name = str(data.get("name", "")).strip()[:80] or "Passkey"
    transports = data.get("transports") if isinstance(data.get("transports"), list) else []
    try:
        credential = passkeys.verify_registration(
            client_data_json=passkeys.b64url_decode(str(data.get("clientDataJSON", ""))),
            attestation_object=passkeys.b64url_decode(str(data.get("attestationObject", ""))),
            challenge=challenge, origin=origin, rp_id=rp_id,
        )
    except passkeys.WebAuthnError as exc:
        audit(request, "passkey.register_failed", user["username"], str(exc), user_id=user["id"])
        return JSONResponse({"error": f"Passkey konnte nicht registriert werden: {exc}"}, status_code=400)
    if credential["credential_id"] != str(data.get("id", "")):
        return JSONResponse({"error": "Credential-ID passt nicht zur Antwort"}, status_code=400)
    try:
        with db() as connection:
            connection.execute(
                "INSERT INTO webauthn_credentials(user_id,credential_id,public_key,algorithm,sign_count,name,"
                "aaguid,transports,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (user["id"], credential["credential_id"], credential["public_key"], credential["algorithm"],
                 credential["sign_count"], name, credential["aaguid"],
                 ",".join(str(item)[:20] for item in transports[:8]), now_iso()),
            )
    except sqlite3.IntegrityError:
        return JSONResponse({"error": "Dieser Passkey ist bereits registriert"}, status_code=409)
    audit(request, "passkey.register", user["username"], f"name={name}", user_id=user["id"])
    return JSONResponse({"redirect": f"/account?message={quote('Passkey wurde hinzugefügt')}"})


@router.post("/account/passkeys/{credential_id}/delete")
def passkey_delete(request: Request, credential_id: int, csrf_token: str = Form(...)):
    user = require_user(request)
    verify_csrf(user, csrf_token)
    with db() as connection:
        row = connection.execute(
            "SELECT name FROM webauthn_credentials WHERE id=? AND user_id=?", (credential_id, user["id"])
        ).fetchone()
        if not row:
            raise HTTPException(404)
        connection.execute("DELETE FROM webauthn_credentials WHERE id=?", (credential_id,))
    audit(request, "passkey.delete", user["username"], f"name={row['name']}", user_id=user["id"])
    return RedirectResponse(f"/account?message={quote('Passkey wurde entfernt')}", status_code=303)


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    user = require_user(request)
    verify_csrf(user, csrf_token)
    raw = request.cookies.get("backup_portal_session", "")
    with db() as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(raw),))
    audit(request, "logout")
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("backup_portal_session", path="/")
    return response
