"""The server overview, its activity feed and the storage refresh."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from core import (
    HOME_ROOT, agent_script_asset, db, format_size, parsed_timestamp, system_account_exists,
)
from auth import audit, require_user, verify_csrf
from rendering import checker_results, render
from workers import STORAGE_WAKEUP, backup_target_storage, storage_worker_state


router = APIRouter()


ACTIVITY_LIMIT = 30
ACTIVITY_KINDS = ("all", "backup", "checker", "mirror", "admin")
AUDIT_LABELS = {
    "backup.trigger": "Backup manuell angefordert",
    "backup.download": "Datei aus Backup geladen",
    "backup.archive_download": "Datei aus Archiv geladen",
    "certificate.request": "Zertifikat angefordert",
    "checker.settings": "Checker-Einstellungen geändert",
    "checker.trigger": "Checkerlauf gestartet",
    "cleanup.trigger": "Policy-Cleanup angefordert",
    "mirror.create": "Spiegelziel angelegt",
    "mirror.delete": "Spiegelziel entfernt",
    "mirror.host_key": "Hostschlüssel gepinnt",
    "mirror.trigger": "Replikation angefordert",
    "mirror.update": "Spiegelziel geändert",
    "client.agent_config": "Agent-Konfiguration geändert",
    "client.create": "Server angelegt",
    "client.delete": "Server entfernt",
    "client.onboard": "Server onboarded",
    "client.policy_assign": "Policy zugewiesen",
    "clients.import": "Bestandskonten importiert",
    "cloudflare.credentials": "Cloudflare-Zugang geändert",
    "cloudflare.test": "Cloudflare-Zugang getestet",
    "deployment_token.create": "Deployment-Token erzeugt",
    "deployment_token.revoke": "Deployment-Token widerrufen",
    "deployment_token.view": "Deployment-Befehl angezeigt",
    "login.failed": "Fehlgeschlagene Anmeldung",
    "login.rate_limited": "Anmeldung gesperrt",
    "login.success": "Anmeldung",
    "logout": "Abmeldung",
    "policy.create": "Policy angelegt",
    "policy.delete": "Policy gelöscht",
    "policy.duplicate": "Policy dupliziert",
    "policy.path_add": "Pfadregel ergänzt",
    "policy.path_delete": "Pfadregel entfernt",
    "policy.update": "Policy geändert",
    "storage.refresh": "Speichermessung angefordert",
    "portal.settings": "Portal-Konfiguration geändert",
    "smtp.settings": "SMTP-Einstellungen geändert",
    "user.create": "Benutzer angelegt",
    "user.notifications": "Mailoptionen geändert",
    "user.password_reset": "Passwort zurückgesetzt",
    "user.toggle": "Benutzer aktiviert oder deaktiviert",
}
FAILING_AUDIT_ACTIONS = {"login.failed", "login.rate_limited"}


def backup_event_entry(row: sqlite3.Row) -> dict[str, Any]:
    """Describe one agent event for the activity feed."""
    try:
        payload = json.loads(row["payload"] or "{}")
    except (TypeError, json.JSONDecodeError):
        payload = {}
    facts: list[str] = []
    if row["event"] == "success":
        volume = payload.get("logical_run_bytes")
        if isinstance(volume, int):
            facts.append(format_size(volume))
        duration = payload.get("duration_seconds")
        if isinstance(duration, (int, float)):
            facts.append(f"{duration:.0f} s")
        databases = sum(
            count for count in (
                (payload.get(engine) or {}).get("database_count") for engine in ("mariadb", "postgresql")
            ) if isinstance(count, int)
        )
        if databases:
            facts.append(f"{databases} Datenbanken")
    elif row["event"] == "failure":
        error = str(payload.get("error") or payload.get("error_type") or "").strip()
        phase = str(payload.get("phase") or "").strip()
        facts = [item for item in (f"Phase {phase}" if phase else "", error) if item]
    title = {
        "success": "Backup eingegangen",
        "failure": "Backup fehlgeschlagen",
        "started": "Backup gestartet",
    }[str(row["event"])]
    return {
        "at": parsed_timestamp(row["created_at"]),
        "kind": "backup",
        "status": {"success": "success", "failure": "failure"}.get(str(row["event"]), "running"),
        "title": title,
        "subject": str(row["slug"]),
        "detail": " · ".join(facts),
        "link": f"/clients/{int(row['client_id'])}",
    }


def activity_feed(kind: str = "all", limit: int = ACTIVITY_LIMIT) -> list[dict[str, Any]]:
    """Merge agent events, refusals, checker runs and audit entries into one stream."""
    entries: list[dict[str, Any]] = []
    with db() as connection:
        if kind in {"all", "backup"}:
            for row in connection.execute(
                "SELECT e.created_at,e.event,e.payload,c.slug,c.id AS client_id FROM status_events e "
                "JOIN clients c ON c.id=e.client_id WHERE e.event IN ('started','success','failure') "
                "ORDER BY e.id DESC LIMIT ?",
                (limit,),
            ):
                entries.append(backup_event_entry(row))
            for row in connection.execute(
                "SELECT b.finished_at,b.message,c.slug,c.id AS client_id FROM backup_commands b "
                "JOIN clients c ON c.id=b.client_id WHERE b.status='skipped' "
                "ORDER BY b.id DESC LIMIT ?",
                (limit,),
            ):
                entries.append({
                    "at": parsed_timestamp(row["finished_at"]),
                    "kind": "backup",
                    "status": "skipped",
                    "title": "Backup abgelehnt",
                    "subject": str(row["slug"]),
                    "detail": str(row["message"] or "Intervall noch nicht abgelaufen"),
                    "link": f"/clients/{int(row['client_id'])}",
                })
        if kind in {"all", "checker"}:
            # The checker reports every hour with the same line; in the merged
            # view a few recent runs are enough to keep backups visible.
            checker_limit = limit if kind == "checker" else 3
            for row in connection.execute(
                "SELECT id,mode,status,summary,finished_at FROM checker_runs "
                "WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT ?",
                (checker_limit,),
            ):
                entries.append({
                    "at": parsed_timestamp(row["finished_at"]),
                    "kind": "checker",
                    "status": "success" if row["status"] == "success" else
                              "failure" if row["status"] == "error" else "warning",
                    "title": {
                        "normal": "Checkerlauf", "force": "Force-Report", "dry_run": "Dry-Run",
                        "smtp_check": "SMTP-Prüfung", "smtp_test": "Testmail",
                    }.get(str(row["mode"]), "Checkerlauf"),
                    "subject": "Checker",
                    "detail": str(row["summary"] or ""),
                    "link": f"/checker/runs/{int(row['id'])}",
                })
        if kind in {"all", "mirror"}:
            for row in connection.execute(
                "SELECT r.id,r.status,r.summary,r.finished_at,r.mode,t.name,t.id AS target_id "
                "FROM mirror_runs r JOIN mirror_targets t ON t.id=r.target_id "
                "WHERE r.finished_at IS NOT NULL ORDER BY r.id DESC LIMIT ?",
                (limit if kind == "mirror" else 5,),
            ):
                entries.append({
                    "at": parsed_timestamp(row["finished_at"]),
                    "kind": "mirror",
                    "status": "success" if row["status"] == "success" else "failure",
                    "title": "Replikation manuell" if row["mode"] == "manual" else "Replikation",
                    "subject": str(row["name"]),
                    "detail": str(row["summary"] or ""),
                    "link": f"/mirrors/runs/{int(row['id'])}",
                })
        if kind in {"all", "admin"}:
            for row in connection.execute(
                "SELECT a.created_at,a.action,a.target,a.details,u.username FROM audit_log a "
                "LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT ?",
                (limit,),
            ):
                action = str(row["action"])
                entries.append({
                    "at": parsed_timestamp(row["created_at"]),
                    "kind": "admin",
                    "status": "failure" if action in FAILING_AUDIT_ACTIONS else "info",
                    "title": AUDIT_LABELS.get(action, action),
                    "subject": str(row["target"] or row["username"] or "Portal"),
                    "detail": str(row["username"] or "System"),
                    "link": None,
                })
    entries = [entry for entry in entries if entry["at"]]
    entries.sort(key=lambda entry: entry["at"], reverse=True)
    for entry in entries[:limit]:
        entry["when"] = entry["at"].strftime("%d.%m. %H:%M")
    return entries[:limit]


def agent_state(client: dict[str, Any], current_script_digest: str) -> dict[str, Any]:
    """Classify how far a source server has been converted to the RAVEN agent.

    The rank orders the states from "needs attention" to "done" so the overview
    can be sorted by conversion progress.
    """
    if not client.get("agent_token_hash"):
        return {
            "state": "unconverted", "label": "NICHT UMGERÜSTET", "rank": 0,
            "hint": "Noch kein Agent onboarded; Curl-Deployment ausstehend",
        }
    last_poll = parsed_timestamp(client.get("last_poll_at"))
    if not last_poll or (datetime.now().astimezone() - last_poll).total_seconds() > 180:
        return {
            "state": "offline", "label": "OFFLINE", "rank": 1,
            "hint": f"Letzter Poll {client.get('last_poll_at') or 'nie'}",
        }
    reported = str(client.get("agent_script_sha256") or "")
    if not reported:
        return {
            "state": "legacy", "label": "ALTER AGENT", "rank": 2,
            "hint": "Agent meldet keine Skriptversion; einmalig neu ausrollen",
        }
    if current_script_digest and reported != current_script_digest:
        return {
            "state": "outdated", "label": "AKTUALISIERT SICH", "rank": 3,
            "hint": "Neues Agent-Skript wird beim nächsten Poll übernommen",
        }
    return {"state": "current", "label": "AKTUELL", "rank": 4, "hint": "Agent online und auf Portalstand"}


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request, sort: str = "server", direction: str = "asc", activity: str = "all"
):
    require_user(request)
    sort = sort if sort in {"server", "volume", "storage", "agent"} else "server"
    activity = activity if activity in ACTIVITY_KINDS else "all"
    direction = direction if direction in {"asc", "desc"} else "asc"
    checks = checker_results()
    with db() as connection:
        clients = [dict(row) for row in connection.execute(
            "SELECT c.*,p.name AS policy_name,p.cleanup_enabled,p.retention_days,p.minimum_snapshots_to_keep "
            "FROM clients c LEFT JOIN backup_policies p ON p.id=c.policy_id ORDER BY c.slug"
        ).fetchall()]
    try:
        current_script_digest = agent_script_asset()[0]
    except OSError:
        current_script_digest = ""
    counts = {"OK": 0, "STALE": 0, "ERROR": 0, "UNKNOWN": 0}
    pending_agents = 0
    orphaned = 0
    for client in clients:
        client["account_exists"] = system_account_exists(client["username"])
        if not client["account_exists"]:
            orphaned += 1
        agent = agent_state(client, current_script_digest)
        client["agent_state"] = agent["state"]
        client["agent_label"] = agent["label"]
        client["agent_hint"] = agent["hint"]
        client["agent_rank"] = agent["rank"]
        if agent["state"] != "current":
            pending_agents += 1
        result = checks.get(client["username"], {}).get("result", {})
        try:
            agent_payload = json.loads(client.get("last_payload") or "{}")
        except (TypeError, json.JSONDecodeError):
            agent_payload = {}
        status = result.get("status") or ("RUNNING" if client["last_event"] == "started" else client["last_event"] or "UNKNOWN")
        status = str(status).upper()
        client["status"] = status
        client["result"] = result
        raw_volume = result.get("volume_bytes")
        volume_source = "Checker · letztes Backup"
        if raw_volume is None:
            raw_volume = agent_payload.get("protected_logical_bytes")
            volume_source = "Agent · geschützte Nutzdaten"
        if raw_volume is None:
            raw_volume = agent_payload.get("logical_run_bytes")
            volume_source = "Agent · gespeicherter Lauf"
        try:
            volume_bytes = int(raw_volume) if raw_volume is not None else None
            if volume_bytes is not None and volume_bytes < 0:
                volume_bytes = None
        except (TypeError, ValueError):
            volume_bytes = None
        client["volume_bytes"] = volume_bytes
        client["volume"] = format_size(volume_bytes)
        client["volume_source"] = volume_source if volume_bytes is not None else "Noch keine Messung"
        client["storage"] = format_size(client.get("storage_bytes"))
        if client.get("storage_error"):
            client["storage_hint"] = f"Messfehler: {client['storage_error']}"
        elif client.get("storage_checked_at"):
            client["storage_hint"] = f"Gesamtes Backup-Home · Stand {client['storage_checked_at']}"
        else:
            client["storage_hint"] = "Messung läuft im Hintergrund"
        client["retention"] = (
            f"{int(client['retention_days'])} Tage · mindestens {int(client['minimum_snapshots_to_keep'])}"
            if client.get("cleanup_enabled") else "Cleanup deaktiviert"
        )
        counts[status if status in counts else "UNKNOWN"] += 1
    if sort == "volume":
        known = [client for client in clients if client["volume_bytes"] is not None]
        unknown = [client for client in clients if client["volume_bytes"] is None]
        known.sort(key=lambda client: client["slug"])
        known.sort(key=lambda client: client["volume_bytes"], reverse=direction == "desc")
        unknown.sort(key=lambda client: client["slug"])
        clients = known + unknown
    elif sort == "storage":
        known = [client for client in clients if client.get("storage_bytes") is not None]
        unknown = [client for client in clients if client.get("storage_bytes") is None]
        known.sort(key=lambda client: client["slug"])
        known.sort(key=lambda client: int(client["storage_bytes"]), reverse=direction == "desc")
        unknown.sort(key=lambda client: client["slug"])
        clients = known + unknown
    elif sort == "agent":
        clients.sort(key=lambda client: client["slug"])
        clients.sort(key=lambda client: client["agent_rank"], reverse=direction == "desc")
    else:
        clients.sort(key=lambda client: client["slug"], reverse=direction == "desc")
    return render(
        request,
        "dashboard.html",
        {
            "clients": clients,
            "counts": counts,
            "pending_agents": pending_agents,
            "orphaned": orphaned,
            "sort": sort,
            "direction": direction,
            "activity": activity,
            "activity_entries": activity_feed(activity),
            "target_storage": backup_target_storage(),
            "storage_worker": storage_worker_state(),
            "message": request.query_params.get("message", ""),
        },
    )


@router.post("/storage/refresh")
def storage_refresh(request: Request, csrf_token: str = Form(...)):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    state = storage_worker_state()
    if not state.get("running"):
        STORAGE_WAKEUP.set()
    audit(request, "storage.refresh", str(HOME_ROOT), "requested", user_id=user["id"])
    message = "Speichermessung läuft bereits" if state.get("running") else "Speichermessung wurde angefordert"
    return RedirectResponse(f"/?message={quote(message)}", status_code=303)
