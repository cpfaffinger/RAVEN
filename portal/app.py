#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from core import (
    ACME_CONFIG, BASE_DIR, CHECKER_CONFIG_PATH, CHECKER_SCRIPT, CHECKER_STATE, CONFIG, HOME_ROOT,
    PORTAL_FQDN, acme_configuration, db, format_size, hash_password, import_existing_clients,
    init_db, now_iso, token_cipher,
)
from auth import audit, require_user
from rendering import render
from workers import (
    CHECKER_STOP, CHECKER_WAKEUP, MIRROR_STOP, MIRROR_WAKEUP, SCHEDULER_STOP, STORAGE_STOP,
    STORAGE_WAKEUP, checker_loop, discard_stale_mirror_credentials, enqueue_due_schedules,
    mirror_loop, schedule_mirror_retry, scheduler_loop, storage_loop, storage_worker_state,
)
from system_status import MANAGED_SYSTEMD_UNITS, read_acme_state, systemd_unit_details
import routes_auth
import routes_settings
import routes_checker
import routes_dashboard
import routes_mirrors
import routes_explorer
import routes_policies
import routes_clients
import routes_agent_api


# startup rebinds these handles, so they live here with everything that reads them.
# A from-import elsewhere would keep seeing the initial None.
SCHEDULER_THREAD: threading.Thread | None = None
CHECKER_THREAD: threading.Thread | None = None
MIRROR_THREAD: threading.Thread | None = None
STORAGE_THREAD: threading.Thread | None = None

app = FastAPI(title="RAVEN", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=[PORTAL_FQDN])
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.headers.get("content-length") and int(request.headers["content-length"]) > 1_048_576:
        return PlainTextResponse("Request too large", status_code=413)
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.on_event("startup")
def startup() -> None:
    global SCHEDULER_THREAD, CHECKER_THREAD, MIRROR_THREAD, STORAGE_THREAD
    init_db()
    imported = import_existing_clients()
    if imported:
        audit(None, "clients.import", details=f"{imported} bestehende Konten importiert")
    enqueue_due_schedules()
    with db() as connection:
        connection.execute(
            "UPDATE checker_runs SET status='interrupted',finished_at=?,summary='Portal wurde waehrend des Laufs beendet' "
            "WHERE status='running'",
            (now_iso(),),
        )
        connection.execute(
            "UPDATE policy_cleanup_runs SET status='interrupted',finished_at=?,"
            "summary='Portal wurde waehrend des Laufs beendet' WHERE status='running'",
            (now_iso(),),
        )
        interrupted_targets = [
            row["target_id"]
            for row in connection.execute("SELECT DISTINCT target_id FROM mirror_runs WHERE status='running'")
        ]
        connection.execute(
            "UPDATE mirror_runs SET status='interrupted',finished_at=?,summary='Portal wurde waehrend des Laufs beendet' "
            "WHERE status='running'",
            (now_iso(),),
        )
        for target_id in interrupted_targets:
            connection.execute(
                "UPDATE mirror_targets SET last_status='interrupted',last_run_at=?,"
                "last_message='Portal wurde waehrend des Laufs beendet' WHERE id=?",
                (now_iso(), target_id),
            )
            schedule_mirror_retry(connection, target_id)
    SCHEDULER_STOP.clear()
    SCHEDULER_THREAD = threading.Thread(target=scheduler_loop, name="backup-scheduler", daemon=True)
    SCHEDULER_THREAD.start()
    CHECKER_STOP.clear()
    CHECKER_WAKEUP.clear()
    CHECKER_THREAD = threading.Thread(target=checker_loop, name="checker-worker", daemon=True)
    CHECKER_THREAD.start()
    MIRROR_STOP.clear()
    MIRROR_WAKEUP.clear()
    discard_stale_mirror_credentials()
    MIRROR_THREAD = threading.Thread(target=mirror_loop, name="mirror-worker", daemon=True)
    MIRROR_THREAD.start()
    STORAGE_STOP.clear()
    STORAGE_WAKEUP.clear()
    STORAGE_THREAD = threading.Thread(target=storage_loop, name="storage-worker", daemon=True)
    STORAGE_THREAD.start()


@app.on_event("shutdown")
def shutdown() -> None:
    SCHEDULER_STOP.set()
    CHECKER_STOP.set()
    CHECKER_WAKEUP.set()
    MIRROR_STOP.set()
    MIRROR_WAKEUP.set()
    STORAGE_STOP.set()
    STORAGE_WAKEUP.set()
    if SCHEDULER_THREAD:
        SCHEDULER_THREAD.join(timeout=5)
    if CHECKER_THREAD:
        CHECKER_THREAD.join(timeout=5)
    if MIRROR_THREAD:
        MIRROR_THREAD.join(timeout=5)
    if STORAGE_THREAD:
        STORAGE_THREAD.join(timeout=5)


@app.get("/livez")
def liveness() -> JSONResponse:
    """Process-only probe: succeeds while the ASGI application can respond."""
    return JSONResponse({"status": "alive", "service": "backup-portal", "time": now_iso()})


def readiness_result() -> tuple[bool, dict[str, Any]]:
    checks: dict[str, Any] = {}
    try:
        with db() as connection:
            checks["database"] = connection.execute("SELECT 1").fetchone()[0] == 1
    except Exception as exc:
        checks["database"] = False
        checks["database_error"] = type(exc).__name__

    backup_script = Path(CONFIG["paths"]["backup_script"])
    bootstrap_script = Path(CONFIG["paths"]["bootstrap_script"])
    checks["backup_script"] = backup_script.is_file() and os.access(backup_script, os.R_OK)
    checks["bootstrap_script"] = bootstrap_script.is_file() and os.access(bootstrap_script, os.R_OK)
    checks["home_root"] = HOME_ROOT.is_dir() and os.access(HOME_ROOT, os.R_OK | os.W_OK | os.X_OK)
    try:
        token_cipher()
        checks["token_encryption"] = True
    except Exception as exc:
        checks["token_encryption"] = False
        checks["token_encryption_error"] = type(exc).__name__

    checks["checker_state_available"] = CHECKER_STATE.is_file() and os.access(CHECKER_STATE, os.R_OK)
    checks["scheduler"] = bool(SCHEDULER_THREAD and SCHEDULER_THREAD.is_alive())
    checks["mirror_worker"] = bool(MIRROR_THREAD and MIRROR_THREAD.is_alive())
    checks["storage_worker"] = bool(STORAGE_THREAD and STORAGE_THREAD.is_alive())
    checks["checker_script"] = CHECKER_SCRIPT.is_file() and os.access(CHECKER_SCRIPT, os.R_OK)
    checks["checker_config"] = CHECKER_CONFIG_PATH.is_file() and os.access(CHECKER_CONFIG_PATH, os.R_OK)
    checks["checker_worker"] = bool(CHECKER_THREAD and CHECKER_THREAD.is_alive())
    if ACME_CONFIG.get("mode") in {"dns-manual", "dns-cloudflare"}:
        acme_hook = Path(ACME_CONFIG.get("hook", "/opt/backup-portal/acme_dns_hook.py"))
        checks["acme_dns_hook"] = acme_hook.is_file() and os.access(acme_hook, os.R_OK)
    if ACME_CONFIG.get("mode") == "dns-cloudflare":
        try:
            checks["cloudflare_token_configured"] = bool(acme_configuration()["token_configured"])
        except Exception as exc:
            checks["cloudflare_token_configured"] = False
            checks["cloudflare_token_error"] = type(exc).__name__
    critical = [
        "database", "backup_script", "bootstrap_script", "home_root", "token_encryption",
        "scheduler", "checker_script", "checker_config", "checker_worker", "mirror_worker", "storage_worker",
    ]
    if ACME_CONFIG.get("mode") in {"dns-manual", "dns-cloudflare"}:
        critical.append("acme_dns_hook")
    return all(checks.get(name) is True for name in critical), checks


@app.get("/readyz")
def readiness() -> JSONResponse:
    """Dependency probe for traffic admission and monitoring."""
    ready, checks = readiness_result()
    return JSONResponse(
        {"status": "ready" if ready else "not_ready", "service": "backup-portal", "checks": checks, "time": now_iso()},
        status_code=200 if ready else 503,
    )


@app.get("/healthz")
def healthz() -> JSONResponse:
    """Backwards-compatible alias for the readiness probe."""
    return readiness()


@app.get("/processes", response_class=HTMLResponse)
def processes_page(request: Request):
    require_user(request, admin=True)
    managed = [systemd_unit_details(unit) for unit in MANAGED_SYSTEMD_UNITS]
    managed.extend(
        [
            {
                "name": "Backup-Scheduler", "kind": "Portal-Thread",
                "status": "success" if SCHEDULER_THREAD and SCHEDULER_THREAD.is_alive() else "failure",
                "result": "läuft" if SCHEDULER_THREAD and SCHEDULER_THREAD.is_alive() else "gestoppt",
                "started_at": "Portalstart", "finished_at": "", "details": "Zentrale Backup-Zeitplanung",
            },
            {
                "name": "Checker-Worker", "kind": "Portal-Thread",
                "status": "success" if CHECKER_THREAD and CHECKER_THREAD.is_alive() else "failure",
                "result": "läuft" if CHECKER_THREAD and CHECKER_THREAD.is_alive() else "gestoppt",
                "started_at": "Portalstart", "finished_at": "", "details": "Checker- und Policy-Cleanup-Warteschlange",
            },
            {
                "name": "Spiegel-Worker", "kind": "Portal-Thread",
                "status": "success" if MIRROR_THREAD and MIRROR_THREAD.is_alive() else "failure",
                "result": "läuft" if MIRROR_THREAD and MIRROR_THREAD.is_alive() else "gestoppt",
                "started_at": "Portalstart", "finished_at": "", "details": "Replikation auf Spiegelserver",
            },
            {
                "name": "Storage-Worker", "kind": "Portal-Thread",
                "status": "success" if STORAGE_THREAD and STORAGE_THREAD.is_alive() else "failure",
                "result": "läuft" if STORAGE_THREAD and STORAGE_THREAD.is_alive() else "gestoppt",
                "started_at": storage_worker_state().get("started_at") or "Portalstart",
                "finished_at": storage_worker_state().get("finished_at") or "",
                "details": storage_worker_state().get("message") or "Backup-Home-Messung",
            },
        ]
    )
    with db() as connection:
        commands = [dict(row) for row in connection.execute(
            "SELECT bc.*,c.slug FROM backup_commands bc JOIN clients c ON c.id=bc.client_id "
            "ORDER BY bc.id DESC LIMIT 50"
        ).fetchall()]
        checker_runs = [dict(row) for row in connection.execute(
            "SELECT cr.*,u.username AS requested_by_name FROM checker_runs cr "
            "LEFT JOIN users u ON u.id=cr.requested_by ORDER BY cr.id DESC LIMIT 30"
        ).fetchall()]
        cleanup_runs = [dict(row) for row in connection.execute(
            "SELECT pr.*,u.username AS requested_by_name FROM policy_cleanup_runs pr "
            "LEFT JOIN users u ON u.id=pr.requested_by ORDER BY pr.id DESC LIMIT 30"
        ).fetchall()]
        policies = [dict(row) for row in connection.execute(
            "SELECT p.*,COUNT(c.id) AS client_count FROM backup_policies p "
            "LEFT JOIN clients c ON c.policy_id=p.id AND c.active=1 "
            "GROUP BY p.id ORDER BY p.name"
        ).fetchall()]
        blocked_by_policy = {
            int(row["policy_id"]): int(row["blocked_count"])
            for row in connection.execute(
                "SELECT c.policy_id,COUNT(DISTINCT c.id) AS blocked_count FROM clients c "
                "LEFT JOIN backup_commands bc ON bc.client_id=c.id "
                "AND bc.status IN ('queued','claimed','running') "
                "WHERE c.active=1 AND (c.last_event='started' OR bc.id IS NOT NULL) GROUP BY c.policy_id"
            ).fetchall()
            if row["policy_id"] is not None
        }
        cloudflare_tests = [dict(row) for row in connection.execute(
            "SELECT ct.*,u.username AS requested_by_name FROM cloudflare_test_runs ct "
            "LEFT JOIN users u ON u.id=ct.requested_by ORDER BY ct.id DESC LIMIT 20"
        ).fetchall()]
        clients = [dict(row) for row in connection.execute(
            "SELECT slug,last_poll_at,last_event,last_event_at FROM clients WHERE active=1 ORDER BY slug"
        ).fetchall()]
    latest_cleanup_by_policy: dict[int, dict[str, Any]] = {}
    for cleanup_run in cleanup_runs:
        cleanup_run["reclaimed_size"] = format_size(cleanup_run.get("reclaimed_bytes"))
        policy_id = cleanup_run.get("policy_id")
        if policy_id is not None and int(policy_id) not in latest_cleanup_by_policy:
            latest_cleanup_by_policy[int(policy_id)] = cleanup_run
    cleanup_busy = any(run["status"] in {"queued", "running"} for run in cleanup_runs)
    cleanup_busy = cleanup_busy or any(run["status"] in {"queued", "running"} for run in checker_runs)
    for policy in policies:
        policy["blocked_count"] = blocked_by_policy.get(int(policy["id"]), 0)
        policy["latest_cleanup"] = latest_cleanup_by_policy.get(int(policy["id"]))
    online = 0
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=3)
    for client in clients:
        try:
            polled = datetime.fromisoformat(str(client["last_poll_at"]).replace("Z", "+00:00"))
            if polled.tzinfo is None:
                polled = polled.replace(tzinfo=timezone.utc)
            online += polled >= cutoff
        except (TypeError, ValueError):
            pass
    return render(
        request,
        "processes.html",
        {
            "managed": managed,
            "commands": commands,
            "checker_runs": checker_runs,
            "cleanup_runs": cleanup_runs,
            "policies": policies,
            "cleanup_busy": cleanup_busy,
            "cloudflare_tests": cloudflare_tests,
            "acme_job": read_acme_state("job.json"),
            "online_agents": online,
            "agent_count": len(clients),
            "generated_at": now_iso(),
            "message": request.query_params.get("message", ""),
        },
    )


app.include_router(routes_auth.router)
app.include_router(routes_settings.router)
app.include_router(routes_checker.router)
app.include_router(routes_dashboard.router)
app.include_router(routes_mirrors.router)
app.include_router(routes_explorer.router)
app.include_router(routes_policies.router)
app.include_router(routes_clients.router)
app.include_router(routes_agent_api.router)


def create_admin(username: str, password: str, display_name: str = "Administrator") -> None:
    init_db()
    with db() as connection:
        connection.execute(
            "INSERT INTO users(username,display_name,password_hash,role,created_at) VALUES(?,?,?,?,?)",
            (username, display_name, hash_password(password), "admin", now_iso()),
        )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init-admin", "import-clients"])
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password")
    parser.add_argument("--password-stdin", action="store_true")
    args = parser.parse_args()
    if args.command == "init-admin":
        supplied_password = args.password
        if args.password_stdin:
            supplied_password = sys.stdin.readline().rstrip("\r\n")
        if not supplied_password:
            raise SystemExit("--password oder --password-stdin erforderlich")
        create_admin(args.username, supplied_password)
        print("Admin erstellt")
    else:
        init_db()
        print(import_existing_clients())
