"""The scheduler, checker, mirror and storage loops and the work they execute."""

from __future__ import annotations

import codecs
import json
import os
import re
import shutil
import sqlite3
import stat as statlib
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import backup_schedule
import mirror as mirror_module
from runtime_config import effective_settings

from core import (
    CHECKER_CONFIG_PATH, CHECKER_CONFIG_SECTION, CHECKER_SCRIPT, CONFIG, HOME_ROOT, LOG,
    application_settings, checker_cleanup_configuration, db, decrypt_deployment_token, format_size,
    now_iso, parsed_timestamp, smtp_configuration,
)


SCHEDULER_STOP = threading.Event()
CHECKER_STOP = threading.Event()
CHECKER_WAKEUP = threading.Event()
MIRROR_STOP = threading.Event()
MIRROR_WAKEUP = threading.Event()
STORAGE_STOP = threading.Event()
STORAGE_WAKEUP = threading.Event()
STORAGE_STATE_LOCK = threading.Lock()
STORAGE_STATE: dict[str, Any] = {
    "running": False, "started_at": None, "finished_at": None,
    "measured": 0, "errors": 0, "message": "Noch keine Messung",
}

# A mirror that was idle for its whole interval has to catch up on every run
# directory created meanwhile, which for a large store takes many hours on a
# home-line uplink. The limit only catches a hung transfer.
MIRROR_TIMEOUT_SECONDS = 86400
MIRROR_RETRY_HOURS = 12
SILENT_AGENT_HOURS = 48

# Below this the target cannot even hold rsync's temporary files, so a run
# would only end in a broken pipe after a few minutes.
MIRROR_MIN_FREE_BYTES = 1024**3
MIRROR_OUTPUT_LIMIT = 250_000
MIRROR_PUBLISH_SECONDS = 2.0


def policy_payload(connection: sqlite3.Connection, policy_id: int | None) -> dict[str, Any]:
    policy = connection.execute(
        "SELECT * FROM backup_policies WHERE id=? AND active=1",
        (policy_id,),
    ).fetchone()
    if not policy:
        raise RuntimeError("Client besitzt keine aktive Backup-Policy")
    paths = connection.execute(
        "SELECT source_path,target_name,mode FROM policy_paths WHERE policy_id=? ORDER BY sort_order,id",
        (policy["id"],),
    ).fetchall()
    return {
        "id": policy["id"],
        "name": policy["name"],
        "mariadb_enabled": bool(policy["mariadb_databases_enabled"] or policy["mariadb_users_enabled"]),
        "mariadb_databases_enabled": bool(policy["mariadb_databases_enabled"]),
        "mariadb_users_enabled": bool(policy["mariadb_users_enabled"]),
        "postgresql_databases_enabled": bool(policy["postgresql_databases_enabled"]),
        "postgresql_roles_enabled": bool(policy["postgresql_roles_enabled"]),
        "schedule_hour": int(policy["schedule_hour"]),
        "schedule_minute": int(policy["schedule_minute"]),
        "interval_hours": int(policy["interval_hours"]),
        "start_offset_minutes": int(policy["start_offset_minutes"]),
        "mail_on_success": bool(policy["mail_on_success"]),
        "mail_on_failure": bool(policy["mail_on_failure"]),
        "mail_on_skipped": bool(policy["mail_on_skipped"]),
        "cleanup_enabled": bool(policy["cleanup_enabled"]),
        "retention_days": int(policy["retention_days"]),
        "minimum_snapshots_to_keep": int(policy["minimum_snapshots_to_keep"]),
        "paths": [dict(row) for row in paths],
    }


def policy_schedule(connection: sqlite3.Connection, policy_id: int | None) -> tuple[int, int, int, int]:
    """Return hour, minute, interval and start offset of a policy with defaults."""
    policy = connection.execute(
        "SELECT schedule_hour,schedule_minute,interval_hours,start_offset_minutes "
        "FROM backup_policies WHERE id=?",
        (policy_id,),
    ).fetchone()
    if not policy:
        defaults = effective_settings(CONFIG)
        return (
            int(defaults["default_schedule_hour"]),
            int(defaults["default_schedule_minute"]),
            int(defaults["default_interval_hours"]),
            0,
        )
    return (
        int(policy["schedule_hour"]),
        int(policy["schedule_minute"]),
        int(policy["interval_hours"]),
        int(policy["start_offset_minutes"]),
    )


def client_schedule_state(
    connection: sqlite3.Connection, client: sqlite3.Row, now: datetime | None = None
) -> dict[str, Any]:
    """Return the live schedule of a client including its next due time."""
    hour, minute, interval_hours, offset = policy_schedule(connection, client["policy_id"])
    state = backup_schedule.schedule_state(
        now or datetime.now().astimezone(),
        parsed_timestamp(client["last_success_at"]),
        hour,
        minute,
        interval_hours,
        offset,
        str(client["slug"]),
    )
    state["description"] = backup_schedule.describe(hour, minute, interval_hours, offset)
    state["next_due_display"] = datetime.fromisoformat(state["next_due_at"]).strftime("%d.%m.%Y %H:%M")
    return state


def enqueue_due_schedules() -> None:
    local_now = datetime.now().astimezone()
    with db() as connection:
        # Short intervals produce one bookkeeping row per slot; drop the old ones
        # so the command history stays readable and bounded.
        connection.execute(
            "DELETE FROM backup_commands WHERE status='satisfied' AND requested_at<?",
            ((local_now - timedelta(days=30)).isoformat(),),
        )
        clients = connection.execute(
            "SELECT * FROM clients WHERE active=1 AND agent_token_hash IS NOT NULL"
        ).fetchall()
        for client in clients:
            if connection.execute(
                "SELECT 1 FROM policy_cleanup_runs WHERE policy_id=? AND status IN ('queued','running')",
                (client["policy_id"],),
            ).fetchone():
                continue
            hour, minute, interval_hours, offset = policy_schedule(connection, client["policy_id"])
            plan = backup_schedule.slot_plan(
                local_now, hour, minute, interval_hours, offset, str(client["slug"])
            )
            current_slot = plan["window_start"]
            last_success = parsed_timestamp(client["last_success_at"])
            due = last_success is None or last_success < current_slot
            schedule_key = f"{client['id']}:{current_slot.isoformat()}"
            if connection.execute("SELECT 1 FROM backup_commands WHERE schedule_key=?", (schedule_key,)).fetchone():
                continue
            # With a start offset the slot opens before its planned moment; wait
            # for that moment so the sources do not all begin at once.
            if due and local_now < plan["planned_start"]:
                continue
            if not due:
                connection.execute(
                    "INSERT OR IGNORE INTO backup_commands(client_id,reason,status,due_at,schedule_key,"
                    "requested_at,finished_at,message) VALUES(?, 'schedule', 'satisfied', ?, ?, ?, ?, ?)",
                    (
                        client["id"], current_slot.isoformat(), schedule_key, now_iso(), now_iso(),
                        "Backup fuer dieses Intervall bereits erfolgreich",
                    ),
                )
                continue
            active = connection.execute(
                "SELECT 1 FROM backup_commands WHERE client_id=? AND status IN ('queued','claimed','running')",
                (client["id"],),
            ).fetchone()
            if active or client["last_event"] == "started":
                continue
            connection.execute(
                "INSERT OR IGNORE INTO backup_commands(client_id,reason,status,due_at,schedule_key,"
                "policy_snapshot,requested_at) VALUES(?, 'schedule', 'queued', ?, ?, ?, ?)",
                (
                    client["id"],
                    current_slot.isoformat(),
                    schedule_key,
                    json.dumps(policy_payload(connection, client["policy_id"]), ensure_ascii=False),
                    now_iso(),
                ),
            )


def checker_next_time(interval_minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)).isoformat()


def enqueue_checker_run(mode: str, requested_by: int | None = None) -> int | None:
    if mode not in {"normal", "force", "dry_run", "smtp_check", "smtp_test"}:
        raise ValueError("Ungueltiger Checker-Modus")
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        active = connection.execute(
            "SELECT id FROM checker_runs WHERE status IN ('queued','running') ORDER BY id LIMIT 1"
        ).fetchone()
        cleanup_active = connection.execute(
            "SELECT id FROM policy_cleanup_runs WHERE status IN ('queued','running') ORDER BY id LIMIT 1"
        ).fetchone()
        if active or cleanup_active:
            return None
        cursor = connection.execute(
            "INSERT INTO checker_runs(mode,status,requested_by,requested_at) VALUES(?,'queued',?,?)",
            (mode, requested_by, now_iso()),
        )
        run_id = int(cursor.lastrowid)
    CHECKER_WAKEUP.set()
    return run_id


def enqueue_due_checker() -> None:
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        settings = connection.execute("SELECT * FROM checker_settings WHERE id=1").fetchone()
        if not settings or not settings["enabled"]:
            return
        due = parsed_timestamp(settings["next_run_at"])
        now = datetime.now(timezone.utc)
        if due and due.astimezone(timezone.utc) > now:
            return
        active = connection.execute(
            "SELECT 1 FROM checker_runs WHERE status IN ('queued','running')"
        ).fetchone()
        cleanup_active = connection.execute(
            "SELECT 1 FROM policy_cleanup_runs WHERE status IN ('queued','running')"
        ).fetchone()
        if not active and not cleanup_active:
            connection.execute(
                "INSERT INTO checker_runs(mode,status,requested_at) VALUES('normal','queued',?)",
                (now_iso(),),
            )
        interval = max(5, min(1440, int(settings["interval_minutes"])))
        connection.execute(
            "UPDATE checker_settings SET next_run_at=?,updated_at=? WHERE id=1",
            (checker_next_time(interval), now_iso()),
        )


def claim_checker_run() -> sqlite3.Row | None:
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM checker_runs WHERE status='running'").fetchone():
            return None
        if connection.execute("SELECT 1 FROM policy_cleanup_runs WHERE status='running'").fetchone():
            return None
        run = connection.execute(
            "SELECT * FROM checker_runs WHERE status='queued' ORDER BY id LIMIT 1"
        ).fetchone()
        if not run:
            return None
        connection.execute(
            "UPDATE checker_runs SET status='running',started_at=? WHERE id=? AND status='queued'",
            (now_iso(), run["id"]),
        )
        return connection.execute("SELECT * FROM checker_runs WHERE id=?", (run["id"],)).fetchone()


def write_run_payload(name: str, run: sqlite3.Row, payload: dict[str, Any]) -> Path:
    """Hand a root-only JSON payload to the checker process."""
    path = Path(f"/run/backup-portal-{name}-{os.getpid()}-{int(run['id'])}.json")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)
        handle.write("\n")
    return path


def checker_mirror_states() -> dict[str, Any]:
    """Return the enabled mirrors so a failed replication alarms like a stale backup."""
    with db() as connection:
        rows = connection.execute(
            "SELECT t.name,t.interval_hours,t.last_status,t.last_message,t.last_run_at,"
            "(SELECT MAX(r.finished_at) FROM mirror_runs r WHERE r.target_id=t.id AND r.status='success') "
            "AS last_success_at FROM mirror_targets t WHERE t.enabled=1 ORDER BY t.id"
        ).fetchall()
    return {"mirrors": [dict(row) for row in rows]}


def checker_age_limits() -> dict[str, float]:
    """Return the backup age per target account after which the checker alarms."""
    with db() as connection:
        clients = connection.execute("SELECT username,policy_id FROM clients WHERE active=1").fetchall()
        limits: dict[str, float] = {}
        for client in clients:
            _hour, _minute, interval_hours, offset = policy_schedule(connection, client["policy_id"])
            limits[str(client["username"])] = backup_schedule.checker_max_age_hours(interval_hours, offset)
    return limits


def checker_alert_settings() -> dict[str, Any]:
    """Return the portal-managed mail triggers of the checker."""
    with db() as connection:
        row = connection.execute("SELECT * FROM checker_settings WHERE id=1").fetchone()
    if not row:
        return {}
    return {
        "mail_on_problem": bool(row["mail_on_problem"]),
        "mail_on_recovery": bool(row["mail_on_recovery"]),
        "mail_on_clean_run": bool(row["mail_on_clean_run"]),
        "alarm_on_unchanged": bool(row["alarm_on_unchanged"]),
        "reminder_hours": int(row["reminder_hours"]),
    }


def checker_cleanup_policies() -> dict[str, dict[str, Any]]:
    """Return retention settings per isolated backup target account."""
    with db() as connection:
        rows = connection.execute(
            "SELECT c.username,p.cleanup_enabled,p.retention_days,p.minimum_snapshots_to_keep "
            "FROM clients c JOIN backup_policies p ON p.id=c.policy_id WHERE c.active=1"
        ).fetchall()
    return {
        str(row["username"]): {
            "enabled": bool(row["cleanup_enabled"]),
            "retention_days": int(row["retention_days"]),
            "minimum_snapshots_to_keep": int(row["minimum_snapshots_to_keep"]),
        }
        for row in rows
    }


def enqueue_policy_cleanup_run(
    policy_id: int, requested_by: int, *, dry_run: bool,
) -> tuple[int | None, str]:
    """Queue one policy-scoped cleanup while excluding checker and backup races."""
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        policy = connection.execute(
            "SELECT id,name,retention_days,minimum_snapshots_to_keep FROM backup_policies WHERE id=?",
            (policy_id,),
        ).fetchone()
        if not policy:
            return None, "not_found"
        client_count = int(connection.execute(
            "SELECT COUNT(*) FROM clients WHERE policy_id=? AND active=1", (policy_id,)
        ).fetchone()[0])
        if client_count == 0:
            return None, "no_clients"
        active_maintenance = connection.execute(
            "SELECT 1 FROM checker_runs WHERE status IN ('queued','running') UNION ALL "
            "SELECT 1 FROM policy_cleanup_runs WHERE status IN ('queued','running') LIMIT 1"
        ).fetchone()
        if active_maintenance:
            return None, "maintenance_busy"
        active_backup = connection.execute(
            "SELECT 1 FROM clients c WHERE c.policy_id=? AND c.active=1 AND "
            "(c.last_event='started' OR EXISTS (SELECT 1 FROM backup_commands bc WHERE bc.client_id=c.id "
            "AND bc.status IN ('queued','claimed','running'))) LIMIT 1",
            (policy_id,),
        ).fetchone()
        if active_backup:
            return None, "backup_active"
        cursor = connection.execute(
            "INSERT INTO policy_cleanup_runs(policy_id,policy_name,dry_run,status,requested_by,requested_at) "
            "VALUES(?,?,?,'queued',?,?)",
            (policy_id, str(policy["name"]), bool(dry_run), requested_by, now_iso()),
        )
        run_id = int(cursor.lastrowid)
    CHECKER_WAKEUP.set()
    return run_id, "queued"


def claim_policy_cleanup_run() -> sqlite3.Row | None:
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute(
            "SELECT 1 FROM policy_cleanup_runs WHERE status='running'"
        ).fetchone():
            return None
        if connection.execute("SELECT 1 FROM checker_runs WHERE status='running'").fetchone():
            return None
        run = connection.execute(
            "SELECT * FROM policy_cleanup_runs WHERE status='queued' ORDER BY id LIMIT 1"
        ).fetchone()
        if not run:
            return None
        connection.execute(
            "UPDATE policy_cleanup_runs SET status='running',started_at=? WHERE id=? AND status='queued'",
            (now_iso(), run["id"]),
        )
        return connection.execute(
            "SELECT * FROM policy_cleanup_runs WHERE id=?", (run["id"],)
        ).fetchone()


def policy_cleanup_payload(policy_id: int) -> dict[str, dict[str, Any]]:
    """Build a strictly scoped manual cleanup map; manual execution overrides auto-disable."""
    with db() as connection:
        rows = connection.execute(
            "SELECT c.username,p.retention_days,p.minimum_snapshots_to_keep "
            "FROM clients c JOIN backup_policies p ON p.id=c.policy_id "
            "WHERE c.active=1 AND p.id=? ORDER BY c.username",
            (policy_id,),
        ).fetchall()
    return {
        str(row["username"]): {
            "enabled": True,
            "retention_days": int(row["retention_days"]),
            "minimum_snapshots_to_keep": int(row["minimum_snapshots_to_keep"]),
        }
        for row in rows
    }


def execute_policy_cleanup_run(run: sqlite3.Row) -> None:
    payload_path: Path | None = None
    timeout = max(60, min(7200, int(CHECKER_CONFIG_SECTION.get("timeout_seconds", 1800))))
    try:
        policy_id = run["policy_id"]
        if policy_id is None:
            raise RuntimeError("Policy wurde vor dem Cleanup entfernt")
        payload = policy_cleanup_payload(int(policy_id))
        if not payload:
            raise RuntimeError("Policy hat keine aktiven Zielkonten")
        payload_path = write_run_payload("policy-cleanup", run, payload)
        command = [
            sys.executable, str(CHECKER_SCRIPT), "--config", str(CHECKER_CONFIG_PATH),
            "--cleanup-json-file", str(payload_path), "--cleanup-only",
        ]
        if run["dry_run"]:
            command.append("--dry-run")
        process = subprocess.run(
            command, cwd=str(CHECKER_SCRIPT.parent), capture_output=True, text=True,
            errors="replace", timeout=timeout, check=False,
        )
        output = (process.stdout + ("\n" if process.stdout and process.stderr else "") + process.stderr).strip()
        result_payload: dict[str, Any] = {}
        for line in reversed(output.splitlines()):
            if line.startswith("CLEANUP_RESULT_JSON="):
                try:
                    parsed = json.loads(line.split("=", 1)[1])
                    if isinstance(parsed, dict):
                        result_payload = parsed
                except json.JSONDecodeError:
                    pass
                break
        summary = str(result_payload.get("detail") or (
            next((line.strip() for line in reversed(output.splitlines()) if line.strip()), "")
            or f"Cleanup endete mit Status {process.returncode}"
        ))[:1000]
        reclaimed = result_payload.get("volume_bytes")
        reclaimed_bytes = int(reclaimed) if isinstance(reclaimed, int) and reclaimed >= 0 else None
        status = "success" if process.returncode == 0 else "error"
        with db() as connection:
            connection.execute(
                "UPDATE policy_cleanup_runs SET status=?,finished_at=?,exit_code=?,reclaimed_bytes=?,"
                "summary=?,output=? WHERE id=?",
                (status, now_iso(), process.returncode, reclaimed_bytes, summary, output[-250_000:], run["id"]),
            )
            connection.execute(
                "DELETE FROM policy_cleanup_runs WHERE id IN (SELECT id FROM policy_cleanup_runs "
                "ORDER BY id DESC LIMIT -1 OFFSET 100)"
            )
        if status == "success" and not run["dry_run"]:
            STORAGE_WAKEUP.set()
        LOG.info("Policy-Cleanup #%s beendet: %s (%s)", run["id"], status, summary)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        with db() as connection:
            connection.execute(
                "UPDATE policy_cleanup_runs SET status='error',finished_at=?,exit_code=124,summary=?,output=? WHERE id=?",
                (now_iso(), f"Zeitlimit von {timeout} Sekunden überschritten", (stdout + "\n" + stderr)[-250_000:], run["id"]),
            )
    except Exception as exc:
        with db() as connection:
            connection.execute(
                "UPDATE policy_cleanup_runs SET status='error',finished_at=?,exit_code=2,summary=?,output='' WHERE id=?",
                (now_iso(), f"{type(exc).__name__}: {exc}"[:1000], run["id"]),
            )
        LOG.exception("Policy-Cleanup #%s konnte nicht ausgeführt werden", run["id"])
    finally:
        if payload_path:
            try:
                payload_path.unlink()
            except FileNotFoundError:
                pass


def execute_checker_run(run: sqlite3.Row) -> None:
    flags = {
        "normal": ["--verbose"],
        "force": ["--force", "--verbose"],
        "dry_run": ["--dry-run"],
        "smtp_check": ["--check-smtp"],
        "smtp_test": ["--send-test"],
    }
    payload_paths: list[Path] = []
    timeout = max(60, min(7200, int(CHECKER_CONFIG_SECTION.get("timeout_seconds", 1800))))
    try:
        smtp_path = write_run_payload("smtp", run, smtp_configuration())
        payload_paths.append(smtp_path)
        schedule_path = write_run_payload("schedule", run, checker_age_limits())
        payload_paths.append(schedule_path)
        alerts_path = write_run_payload("alerts", run, checker_alert_settings())
        payload_paths.append(alerts_path)
        cleanup_path = write_run_payload("cleanup", run, checker_cleanup_policies())
        payload_paths.append(cleanup_path)
        mirrors_path = write_run_payload("mirrors", run, checker_mirror_states())
        payload_paths.append(mirrors_path)
        command = [
            sys.executable,
            str(CHECKER_SCRIPT),
            "--config",
            str(CHECKER_CONFIG_PATH),
            "--smtp-json-file",
            str(smtp_path),
            "--schedule-json-file",
            str(schedule_path),
            "--alerts-json-file",
            str(alerts_path),
            "--cleanup-json-file",
            str(cleanup_path),
            "--mirrors-json-file",
            str(mirrors_path),
            *flags[str(run["mode"])],
        ]
        process = subprocess.run(
            command,
            cwd=str(CHECKER_SCRIPT.parent),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        output = (process.stdout + ("\n" if process.stdout and process.stderr else "") + process.stderr).strip()
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        summary = (lines[-1] if lines else f"Checker endete mit Status {process.returncode}")[:1000]
        if process.returncode == 0:
            status = "success"
        elif process.returncode == 1 and run["mode"] in {"normal", "force", "dry_run"}:
            status = "problems"
        else:
            status = "error"
        with db() as connection:
            connection.execute(
                "UPDATE checker_runs SET status=?,finished_at=?,exit_code=?,summary=?,output=? WHERE id=?",
                (status, now_iso(), process.returncode, summary, output[-250_000:], run["id"]),
            )
            connection.execute(
                "DELETE FROM checker_runs WHERE id IN (SELECT id FROM checker_runs ORDER BY id DESC LIMIT -1 OFFSET 100)"
            )
        LOG.info("Checker-Lauf #%s beendet: %s (%s)", run["id"], status, summary)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        output = (stdout + "\n" + stderr).strip()
        with db() as connection:
            connection.execute(
                "UPDATE checker_runs SET status='error',finished_at=?,exit_code=124,summary=?,output=? WHERE id=?",
                (now_iso(), f"Zeitlimit von {timeout} Sekunden ueberschritten", output[-250_000:], run["id"]),
            )
        LOG.error("Checker-Lauf #%s hat das Zeitlimit ueberschritten", run["id"])
    except Exception as exc:
        with db() as connection:
            connection.execute(
                "UPDATE checker_runs SET status='error',finished_at=?,exit_code=2,summary=?,output=? WHERE id=?",
                (now_iso(), f"{type(exc).__name__}: {exc}"[:1000], "", run["id"]),
            )
        LOG.exception("Checker-Lauf #%s konnte nicht ausgefuehrt werden", run["id"])
    finally:
        for path in payload_paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def mirror_credentials(target: sqlite3.Row) -> tuple[Path, Path]:
    """Materialise key and known_hosts for one run, readable only by root."""
    key = decrypt_deployment_token(str(target["private_key_ciphertext"]))
    if not key.strip():
        raise RuntimeError("Fuer dieses Ziel ist kein privater Schluessel hinterlegt")
    host_key = str(target["host_key"] or "").strip()
    if not host_key:
        raise RuntimeError("Fuer dieses Ziel ist kein Hostschluessel hinterlegt")
    stamp = f"{os.getpid()}-{int(target['id'])}"
    paths: list[Path] = []
    for name, payload in (("key", key), ("known-hosts", host_key + "\n")):
        path = Path(f"/run/backup-portal-mirror-{name}-{stamp}")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
        paths.append(path)
    return paths[0], paths[1]


def discard_stale_mirror_credentials() -> None:
    """Remove key material a killed replication could not clean up itself.

    A hard stop kills the worker mid-transfer, so its finally block never runs
    and the private key stays behind. Files of the current process are left
    alone; they belong to a replication that is still going.
    """
    for path in Path("/run").glob("backup-portal-mirror-*"):
        if path.name.endswith(f"-{os.getpid()}") or f"-{os.getpid()}-" in path.name:
            continue
        try:
            path.unlink()
            LOG.info("Zurueckgebliebene Spiegel-Zugangsdatei entfernt: %s", path.name)
        except OSError:
            LOG.warning("Zurueckgebliebene Spiegel-Zugangsdatei blieb liegen: %s", path.name)


def mirror_disk_usage(target: sqlite3.Row, key_path: Path, known_hosts_path: Path) -> tuple[int, int]:
    process = subprocess.run(
        mirror_module.ssh_command(
            username=str(target["username"]), host=str(target["host"]),
            remote_command=mirror_module.disk_usage_command(str(target["remote_path"])),
            key_path=str(key_path), known_hosts_path=str(known_hosts_path),
            port=int(target["ssh_port"]),
        ),
        capture_output=True, text=True, errors="replace", timeout=60, check=False,
    )
    if process.returncode != 0:
        raise RuntimeError((process.stderr or "df fehlgeschlagen").strip()[:300])
    return mirror_module.parse_disk_usage(process.stdout)


def enqueue_due_mirrors() -> None:
    now = datetime.now(timezone.utc)
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        for target in connection.execute(
            "SELECT * FROM mirror_targets WHERE enabled=1 AND private_key_ciphertext<>'' AND host_key<>''"
        ).fetchall():
            due = parsed_timestamp(target["next_run_at"])
            if due and due.astimezone(timezone.utc) > now:
                continue
            pending = connection.execute(
                "SELECT 1 FROM mirror_runs WHERE target_id=? AND status IN ('queued','running')",
                (target["id"],),
            ).fetchone()
            if not pending:
                connection.execute(
                    "INSERT INTO mirror_runs(target_id,mode,status,requested_at) VALUES(?,'scheduled','queued',?)",
                    (target["id"], now_iso()),
                )
            interval = max(1, min(mirror_module.MAX_INTERVAL_HOURS, int(target["interval_hours"])))
            connection.execute(
                "UPDATE mirror_targets SET next_run_at=? WHERE id=?",
                ((now + timedelta(hours=interval)).isoformat(), target["id"]),
            )


def claim_mirror_run() -> sqlite3.Row | None:
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM mirror_runs WHERE status='running'").fetchone():
            return None
        run = connection.execute(
            "SELECT * FROM mirror_runs WHERE status='queued' ORDER BY id LIMIT 1"
        ).fetchone()
        if not run:
            return None
        connection.execute(
            "UPDATE mirror_runs SET status='running',started_at=? WHERE id=? AND status='queued'",
            (now_iso(), run["id"]),
        )
        return connection.execute("SELECT * FROM mirror_runs WHERE id=?", (run["id"],)).fetchone()


def schedule_mirror_retry(connection: sqlite3.Connection, target_id: int) -> None:
    """Pull the next attempt forward; the regular interval can be weeks away."""
    retry_at = (datetime.now(timezone.utc) + timedelta(hours=MIRROR_RETRY_HOURS)).isoformat()
    connection.execute(
        "UPDATE mirror_targets SET next_run_at=? WHERE id=? AND next_run_at>?",
        (retry_at, target_id, retry_at),
    )


def finish_mirror_run(
    run_id: int, target_id: int, status: str, *, exit_code: int | None,
    summary: str, output: str, transferred: int | None = None,
) -> None:
    with db() as connection:
        connection.execute(
            "UPDATE mirror_runs SET status=?,finished_at=?,exit_code=?,transferred_bytes=?,summary=?,output=? "
            "WHERE id=?",
            (status, now_iso(), exit_code, transferred, summary[:1000], output[-250_000:], run_id),
        )
        connection.execute(
            "UPDATE mirror_targets SET last_status=?,last_run_at=?,last_message=? WHERE id=?",
            (status, now_iso(), summary[:1000], target_id),
        )
        if status != "success":
            schedule_mirror_retry(connection, target_id)
        connection.execute(
            "DELETE FROM mirror_runs WHERE target_id=? AND id IN "
            "(SELECT id FROM mirror_runs WHERE target_id=? ORDER BY id DESC LIMIT -1 OFFSET 50)",
            (target_id, target_id),
        )


def execute_mirror_run(run: sqlite3.Row) -> None:
    """Replicate the newest runs or the whole backup store to one mirror."""
    run_id = int(run["id"])
    target_id = int(run["target_id"])
    with db() as connection:
        target = connection.execute("SELECT * FROM mirror_targets WHERE id=?", (target_id,)).fetchone()
    if not target:
        finish_mirror_run(run_id, target_id, "failure", exit_code=None,
                          summary="Spiegelziel existiert nicht mehr", output="")
        return
    sections: list[str] = []
    key_path: Path | None = None
    known_hosts_path: Path | None = None

    def publish_progress(parts: list[str]) -> None:
        """Make the output of the running replication visible right away."""
        try:
            with db() as connection:
                connection.execute(
                    "UPDATE mirror_runs SET output=? WHERE id=?",
                    (chr(10).join(part for part in parts if part)[-MIRROR_OUTPUT_LIMIT:], run_id),
                )
        except sqlite3.Error:
            LOG.debug("Zwischenstand des Spiegellaufs konnte nicht gespeichert werden", exc_info=True)

    try:
        options = mirror_module.validated_rsync_options(str(target["rsync_options"]))
        key_path, known_hosts_path = mirror_credentials(target)
        try:
            total, free = mirror_disk_usage(target, key_path, known_hosts_path)
            with db() as connection:
                connection.execute(
                    "UPDATE mirror_targets SET total_bytes=?,free_bytes=?,space_checked_at=? WHERE id=?",
                    (total, free, now_iso(), target_id),
                )
            sections.append(f"Zielspeicher: {format_size(free)} frei von {format_size(total)}")
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            free = None
            sections.append(f"Zielspeicher konnte nicht gelesen werden: {exc}")
        if free is not None and free < MIRROR_MIN_FREE_BYTES:
            summary = (
                f"Zielspeicher auf {target['host']} ist voll ({format_size(free)} frei); "
                "Replikation nicht gestartet"
            )
            finish_mirror_run(
                run_id, target_id, "failure", exit_code=None, summary=summary, output="\n\n".join(sections),
            )
            LOG.error("Spiegelreplikation %s: %s", target["name"], summary)
            return
        account_prefix = str(application_settings()["username_prefix"])
        latest = str(target["strategy"]) == "latest"
        selection = mirror_module.latest_runs(HOME_ROOT, account_prefix) if latest else None
        if selection is not None:
            sections.append(
                "Neuester Stand je Host:\n" + "\n".join(
                    f"{account}: {run or 'kein vollständiger Lauf, Spiegel bleibt unverändert'}"
                    for account, run in selection.items()
                )
            )
            seed = subprocess.run(
                mirror_module.ssh_command(
                    username=str(target["username"]), host=str(target["host"]),
                    remote_command=mirror_module.seed_command(str(target["remote_path"]), selection),
                    key_path=str(key_path), known_hosts_path=str(known_hosts_path),
                    port=int(target["ssh_port"]),
                ),
                capture_output=True, text=True, errors="replace", timeout=1800, check=False,
            )
            seeded = [line for line in seed.stdout.splitlines() if line.strip()]
            sections.append(
                f"Als Basis vom vorherigen Stand übernommen ({len(seeded)}):\n" + "\n".join(seeded)
                if seeded else "Kein vorheriger Stand als Basis übernommen"
            )
            if seed.returncode != 0:
                sections.append(f"Vorbereitung auf dem Ziel endete mit Status {seed.returncode}: {seed.stderr.strip()}")
        command = mirror_module.rsync_command(
            source_path=str(HOME_ROOT), username=str(target["username"]), host=str(target["host"]),
            remote_path=str(target["remote_path"]), options=options,
            key_path=str(key_path), known_hosts_path=str(known_hosts_path),
            port=int(target["ssh_port"]), account_prefix=account_prefix, selection=selection,
        )
        LOG.info("Spiegelreplikation %s gestartet: %s", target["name"], target["host"])
        publish_progress(sections + ["rsync laeuft ..."])
        return_code, transfer_output = run_streaming(
            command,
            MIRROR_TIMEOUT_SECONDS,
            lambda text: publish_progress(sections + [text]),
        )
        transferred = mirror_module.parse_transferred_bytes(transfer_output)
        sections.append(transfer_output.strip())
        publish_progress(sections)
        # rsync reports 24 when a file vanished mid-transfer; a live backup store
        # does that regularly and the replication itself is still complete.
        acceptable = return_code in {0, 24}
        # The latest strategy already removed every older run with --delete.
        if acceptable and not latest and int(target["retention_days"]) > 0:
            prune = subprocess.run(
                mirror_module.ssh_command(
                    username=str(target["username"]), host=str(target["host"]),
                    remote_command=mirror_module.retention_command(
                        str(target["remote_path"]), int(target["retention_days"])
                    ),
                    key_path=str(key_path), known_hosts_path=str(known_hosts_path),
                    port=int(target["ssh_port"]),
                ),
                capture_output=True, text=True, errors="replace", timeout=1800, check=False,
            )
            removed = [line for line in prune.stdout.splitlines() if line.strip()]
            sections.append(
                f"Aufbewahrung {int(target['retention_days'])} Tage: {len(removed)} Laeufe entfernt\n"
                + "\n".join(removed[:200])
            )
            publish_progress(sections)
        if acceptable:
            # Entries outside the backup accounts are not replicated. Anything an
            # earlier run copied there stays untouched, so name it instead of
            # deleting data on a remote host on our own initiative.
            foreign = subprocess.run(
                mirror_module.ssh_command(
                    username=str(target["username"]), host=str(target["host"]),
                    remote_command=mirror_module.foreign_entries_command(
                        str(target["remote_path"]), account_prefix
                    ),
                    key_path=str(key_path), known_hosts_path=str(known_hosts_path),
                    port=int(target["ssh_port"]),
                ),
                capture_output=True, text=True, errors="replace", timeout=120, check=False,
            )
            names = [line for line in foreign.stdout.splitlines() if line.strip()]
            if names:
                sections.append(
                    f"Nicht repliziert und weiterhin auf dem Ziel vorhanden ({len(names)}): "
                    + ", ".join(names)
                )
        status = "success" if acceptable else "failure"
        summary = (
            f"{'Neuester Stand' if latest else 'Replikation'} nach {target['host']} abgeschlossen"
            + (f", {format_size(transferred)} uebertragen" if transferred is not None else "")
            if acceptable
            else f"rsync endete mit Status {return_code}"
        )
        finish_mirror_run(
            run_id, target_id, status, exit_code=return_code,
            summary=summary, output="\n\n".join(sections), transferred=transferred,
        )
        LOG.info("Spiegelreplikation %s beendet: %s", target["name"], summary)
    except subprocess.TimeoutExpired as exc:
        partial = exc.output.decode("utf-8", "replace") if isinstance(exc.output, bytes) else (exc.output or "")
        finish_mirror_run(
            run_id, target_id, "failure", exit_code=124,
            summary=f"Zeitlimit von {MIRROR_TIMEOUT_SECONDS} Sekunden ueberschritten",
            output="\n\n".join([*sections, partial]),
        )
        LOG.error("Spiegelreplikation %s hat das Zeitlimit ueberschritten", target["name"])
    except Exception as exc:
        finish_mirror_run(
            run_id, target_id, "failure", exit_code=2,
            summary=f"{type(exc).__name__}: {exc}", output="\n\n".join(sections),
        )
        LOG.exception("Spiegelreplikation %s fehlgeschlagen", target["name"])
    finally:
        for path in (key_path, known_hosts_path):
            if path:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass


def run_streaming(command: list[str], timeout: int, publish: Any) -> tuple[int, str]:
    """Run a command and hand its output on while it is still running.

    Output is read in chunks rather than by line so a carriage return progress
    display arrives as well, and only the tail is kept so a chatty transfer
    cannot grow without a bound.
    """
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    timed_out = threading.Event()
    timer = threading.Timer(timeout, lambda: (timed_out.set(), process.kill()))
    timer.start()
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    lines: list[str] = []
    pending = ""
    size = 0
    truncated = False
    published_at = 0.0

    def collected() -> str:
        body = "\n".join(lines)
        return "[... aeltere Zeilen wegen Groessenlimit entfernt ...]" + "\n" + body if truncated else body

    try:
        assert process.stdout is not None
        while True:
            data = os.read(process.stdout.fileno(), 65536)
            if not data:
                break
            pending += decoder.decode(data)
            *complete, pending = re.split(r"\r\n|\r|\n", pending)
            for line in complete:
                lines.append(line)
                size += len(line) + 1
            while size > MIRROR_OUTPUT_LIMIT and lines:
                size -= len(lines.pop(0)) + 1
                truncated = True
            now = time.monotonic()
            if complete and now - published_at >= MIRROR_PUBLISH_SECONDS:
                published_at = now
                publish(collected())
        if pending.strip():
            lines.append(pending)
        return_code = process.wait(timeout=60)
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.stdout:
            process.stdout.close()
    if timed_out.is_set():
        raise subprocess.TimeoutExpired(command, timeout, output=collected().encode("utf-8", "replace"))
    return return_code, collected()


def mirror_loop() -> None:
    while not MIRROR_STOP.is_set():
        try:
            enqueue_due_mirrors()
            run = claim_mirror_run()
            if run:
                execute_mirror_run(run)
                continue
        except Exception:
            LOG.exception("Spiegel-Worker fehlgeschlagen")
        MIRROR_WAKEUP.wait(30)
        MIRROR_WAKEUP.clear()


def measure_client_storage(client: sqlite3.Row) -> int:
    """Measure allocated bytes below one direct, non-symlinked backup home."""
    root = HOME_ROOT.resolve(strict=True)
    home = Path(str(client["home_path"]))
    metadata = home.lstat()
    if statlib.S_ISLNK(metadata.st_mode) or not statlib.S_ISDIR(metadata.st_mode):
        raise RuntimeError("Backup-Home ist kein direktes Verzeichnis")
    if home.parent.resolve(strict=True) != root or home.name != str(client["username"]):
        raise RuntimeError("Backup-Home liegt nicht direkt unter dem Home-Root")
    process = subprocess.run(
        ["/usr/bin/du", "--summarize", "--block-size=1", "--one-file-system", "--", str(home)],
        capture_output=True, text=True, errors="replace", timeout=600, check=False,
    )
    if process.returncode != 0:
        raise RuntimeError((process.stderr or f"du endete mit Status {process.returncode}").strip()[:500])
    try:
        return int(process.stdout.split(maxsplit=1)[0])
    except (IndexError, ValueError) as exc:
        raise RuntimeError("Ungültige du-Ausgabe") from exc


def refresh_client_storage() -> None:
    started_at = now_iso()
    with STORAGE_STATE_LOCK:
        STORAGE_STATE.update(
            {"running": True, "started_at": started_at, "measured": 0, "errors": 0, "message": "Messung läuft"}
        )
    measured = 0
    errors = 0
    with db() as connection:
        clients = connection.execute(
            "SELECT id,username,home_path FROM clients WHERE active=1 ORDER BY username"
        ).fetchall()
    for client in clients:
        if STORAGE_STOP.is_set():
            break
        checked_at = now_iso()
        try:
            storage_bytes = measure_client_storage(client)
            with db() as connection:
                connection.execute(
                    "UPDATE clients SET storage_bytes=?,storage_checked_at=?,storage_error='' WHERE id=?",
                    (storage_bytes, checked_at, client["id"]),
                )
            measured += 1
        except Exception as exc:
            with db() as connection:
                connection.execute(
                    "UPDATE clients SET storage_checked_at=?,storage_error=? WHERE id=?",
                    (checked_at, f"{type(exc).__name__}: {exc}"[:500], client["id"]),
                )
            errors += 1
            LOG.warning("Speichermessung für %s fehlgeschlagen: %s", client["username"], exc)
    finished_at = now_iso()
    with STORAGE_STATE_LOCK:
        STORAGE_STATE.update(
            {
                "running": False, "finished_at": finished_at, "measured": measured, "errors": errors,
                "message": f"{measured} Homes gemessen, {errors} Fehler",
            }
        )


def storage_loop() -> None:
    while not STORAGE_STOP.is_set():
        try:
            refresh_client_storage()
        except Exception:
            LOG.exception("Storage-Worker fehlgeschlagen")
            with STORAGE_STATE_LOCK:
                STORAGE_STATE.update({"running": False, "finished_at": now_iso(), "message": "Worker-Fehler"})
        STORAGE_WAKEUP.wait(3600)
        STORAGE_WAKEUP.clear()


def storage_worker_state() -> dict[str, Any]:
    with STORAGE_STATE_LOCK:
        return dict(STORAGE_STATE)


def backup_target_storage() -> dict[str, Any]:
    usage = shutil.disk_usage(HOME_ROOT)
    used = usage.total - usage.free
    free_percent = usage.free / usage.total * 100 if usage.total else 0.0
    threshold = float(checker_cleanup_configuration()["minimum_free_percent"])
    return {
        "path": str(HOME_ROOT),
        "total_bytes": usage.total,
        "used_bytes": used,
        "free_bytes": usage.free,
        "total": format_size(usage.total),
        "used": format_size(used),
        "free": format_size(usage.free),
        "free_percent": round(free_percent, 1),
        "used_percent": round(100.0 - free_percent, 1),
        "minimum_free_percent": threshold,
        "status": "ok" if free_percent >= threshold else "error",
    }


def checker_loop() -> None:
    while not CHECKER_STOP.is_set():
        try:
            enqueue_due_checker()
            cleanup_run = claim_policy_cleanup_run()
            if cleanup_run:
                execute_policy_cleanup_run(cleanup_run)
                continue
            run = claim_checker_run()
            if run:
                execute_checker_run(run)
                continue
        except Exception:
            LOG.exception("Portal-Checker-Worker fehlgeschlagen")
        CHECKER_WAKEUP.wait(10)
        CHECKER_WAKEUP.clear()


def close_dead_run(connection: sqlite3.Connection, client_id: int, message: str) -> None:
    """Release a host whose agent ended a run without reporting its outcome.

    The scheduler and the manual trigger refuse a host with an open run, so an
    agent killed mid-run would otherwise block that host for good.
    """
    closed = connection.execute(
        "UPDATE backup_commands SET status='failure',finished_at=?,message=? WHERE client_id=? AND status='running'",
        (now_iso(), message, client_id),
    ).rowcount
    closed += connection.execute(
        "UPDATE clients SET last_event='failure',last_event_at=? WHERE id=? AND last_event='started'",
        (now_iso(), client_id),
    ).rowcount
    if closed:
        connection.execute(
            "INSERT INTO status_events(client_id,event,run_id,payload,created_at) VALUES(?, 'failure', NULL, ?, ?)",
            (client_id, json.dumps({"error": message}, ensure_ascii=False), now_iso()),
        )


def release_silent_agents() -> None:
    """Close runs of agents that vanished; a late report still overrides the result."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=SILENT_AGENT_HOURS)).isoformat()
    with db() as connection:
        rows = connection.execute(
            "SELECT c.id FROM clients c WHERE (c.last_event='started' AND c.last_event_at<?) OR EXISTS "
            "(SELECT 1 FROM backup_commands bc WHERE bc.client_id=c.id AND bc.status='running' AND bc.started_at<?)",
            (cutoff, cutoff),
        ).fetchall()
        for row in rows:
            close_dead_run(
                connection, row["id"], f"Agent hat sich seit {SILENT_AGENT_HOURS} Stunden nicht gemeldet"
            )


def scheduler_loop() -> None:
    while not SCHEDULER_STOP.wait(30):
        try:
            release_silent_agents()
            enqueue_due_schedules()
        except Exception:
            LOG.exception("Zentraler Backup-Scheduler fehlgeschlagen")
