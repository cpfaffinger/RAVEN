#!/usr/bin/env python3
"""Unified, direct-to-SSH filesystem and MariaDB backup job."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import html
import json
import logging
import os
import shlex
import smtplib
import socket
import subprocess
import sys
import time
import traceback
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.parse import quote

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 on supported older Ubuntu releases
    import tomli as tomllib


SYSTEM_DATABASES = {"information_schema", "performance_schema", "mysql", "sys"}
DEFAULT_STATE_PATH = "/var/lib/raven-backup/agent-state.json"
DEFAULT_INTERVAL_HOURS = 24
LOG = logging.getLogger("raven-backup")
CURRENT_PHASE = "startup"
CURRENT_RUN_ID: str | None = None
CURRENT_COMMAND_ID: int | None = None
ATTEMPT_STARTED_AT: str | None = None
LOG_UPLOAD_ID = uuid.uuid4().hex
PORTAL_LOG_HANDLER: "BoundedLogHandler | None" = None


def format_size(value: int, *, signed: bool = False) -> str:
    sign = "-" if value < 0 else "+" if signed and value > 0 else ""
    amount = float(abs(value))
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    unit = units[0]
    for candidate in units:
        unit = candidate
        if amount < 1024 or candidate == units[-1]:
            break
        amount /= 1024
    precision = 0 if unit == "B" else 2
    return f"{sign}{amount:.{precision}f} {unit}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/root/backup-job.toml")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--check-status", action="store_true", help="Portal-Verbindung testen, ohne Backup zu starten")
    parser.add_argument("--poll", action="store_true", help="Zentralen Backup-Auftrag abfragen und gegebenenfalls ausfuehren")
    parser.add_argument("--test-email", action="store_true")
    parser.add_argument("--notify-success", action="store_true", help="Erfolgsmail fuer diesen Lauf erzwingen")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Backup auch dann ausfuehren, wenn das Intervall der Policy noch nicht abgelaufen ist",
    )
    return parser.parse_args()


def load_config(path: str) -> dict[str, Any]:
    with open(path, "rb") as handle:
        cfg = tomllib.load(handle)
    for name in ("backup", "smtp"):
        if name not in cfg:
            raise ValueError(f"Konfigurationsabschnitt [{name}] fehlt")
    return cfg


def configured_backup_paths(cfg: dict[str, Any]) -> list[dict[str, str]]:
    raw_paths = cfg.get("backup_paths")
    if raw_paths is None:
        return [
            {"source_path": str(source), "target_name": Path(str(source)).name, "mode": "tar"}
            for source in cfg["backup"].get("sources", ["/etc", "/home"])
        ]
    normalized: list[dict[str, str]] = []
    seen_targets: set[str] = set()
    for raw in raw_paths:
        source = str(raw.get("source_path", "")).rstrip("/") or "/"
        target = str(raw.get("target_name", "")).strip()
        mode = str(raw.get("mode", "")).strip()
        if not source.startswith("/") or source == "/" or ".." in Path(source).parts:
            raise ValueError(f"ungueltiger Policy-Quellpfad: {source!r}")
        if not target or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for char in target):
            raise ValueError(f"ungueltiger Policy-Zielname: {target!r}")
        if target in seen_targets:
            raise ValueError(f"doppelter Policy-Zielname: {target}")
        if mode not in {"sync", "snapshot", "tar"}:
            raise ValueError(f"ungueltiger Policy-Modus fuer {source}: {mode}")
        if mode == "snapshot":
            mode = "tar"
        seen_targets.add(target)
        normalized.append({"source_path": source, "target_name": target, "mode": mode})
    return normalized


def apply_command_policy(cfg: dict[str, Any], command: dict[str, Any]) -> None:
    policy = command.get("policy")
    if not isinstance(policy, dict):
        return
    paths = policy.get("paths")
    if not isinstance(paths, list):
        raise RuntimeError("Zentraler Auftrag enthaelt keine gueltige Policy")
    cfg["backup_paths"] = paths
    cfg["backup"]["policy_id"] = int(policy["id"])
    cfg["backup"]["policy_name"] = str(policy["name"])
    mariadb_available = bool(cfg["backup"].get("mariadb_available", cfg["backup"].get("mariadb_enabled", True)))
    legacy_enabled = bool(policy.get("mariadb_enabled", True))
    databases_enabled = mariadb_available and bool(policy.get("mariadb_databases_enabled", legacy_enabled))
    users_enabled = mariadb_available and bool(policy.get("mariadb_users_enabled", legacy_enabled))
    cfg["backup"]["mariadb_databases_enabled"] = databases_enabled
    cfg["backup"]["mariadb_users_enabled"] = users_enabled
    cfg["backup"]["mariadb_enabled"] = databases_enabled or users_enabled


class BoundedLogHandler(logging.Handler):
    def __init__(self, max_bytes: int) -> None:
        super().__init__()
        self.max_bytes = max(16 * 1024, min(512 * 1024, int(max_bytes)))
        self.buffer = bytearray()
        self.truncated = False

    def emit(self, record: logging.LogRecord) -> None:
        self.acquire()
        try:
            encoded = (self.format(record) + "\n").encode("utf-8", "replace")
            self.buffer.extend(encoded)
            if len(self.buffer) > self.max_bytes:
                del self.buffer[: len(self.buffer) - self.max_bytes]
                self.truncated = True
        except Exception:
            self.handleError(record)
        finally:
            self.release()

    def snapshot(self) -> tuple[str, bool]:
        self.acquire()
        try:
            if self.truncated:
                marker = "[... ältere Logzeilen wegen Größenlimit entfernt ...]\n".encode("utf-8")
                available = max(0, self.max_bytes - len(marker))
                body = bytes(self.buffer[-available:]) if available else b""
                return marker.decode("utf-8") + body.decode("utf-8", "ignore"), True
            return bytes(self.buffer).decode("utf-8", "replace"), False
        finally:
            self.release()


def setup_logging(cfg: dict[str, Any] | None = None) -> None:
    global PORTAL_LOG_HANDLER
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    log_cfg = (cfg or {}).get("logging", {})
    level_name = str(log_cfg.get("level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S%z")
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)
    if bool(log_cfg.get("local_enabled", True)):
        stream = logging.StreamHandler(sys.stdout)
        stream.setFormatter(formatter)
        root.addHandler(stream)
    PORTAL_LOG_HANDLER = None
    if bool(log_cfg.get("portal_enabled", False)):
        PORTAL_LOG_HANDLER = BoundedLogHandler(int(log_cfg.get("portal_max_bytes", 262144)))
        PORTAL_LOG_HANDLER.setFormatter(formatter)
        root.addHandler(PORTAL_LOG_HANDLER)


def run(
    args: list[str],
    *,
    input_text: str | None = None,
    capture: bool = False,
    timeout: float | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    LOG.debug("run: %s", shlex.join(args))
    proc = subprocess.run(
        args,
        input=input_text,
        text=True,
        capture_output=capture,
        timeout=timeout,
        check=False,
    )
    if check and proc.returncode != 0:
        stderr = (proc.stderr or "").strip() if capture else ""
        raise RuntimeError(f"Befehl fehlgeschlagen ({proc.returncode}): {shlex.join(args)}{': ' + stderr if stderr else ''}")
    return proc


def ssh_options(cfg: dict[str, Any]) -> list[str]:
    control_path = str(cfg["backup"].get("ssh_control_path", "/run/raven-backup-ssh-%C"))
    return [
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=20",
        "-o", "ConnectionAttempts=3",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=4",
        "-o", "Compression=yes",
        "-o", "ControlMaster=auto",
        "-o", "ControlPersist=300",
        "-o", f"ControlPath={control_path}",
    ]


def ssh_command(cfg: dict[str, Any], remote_command: str) -> list[str]:
    return ["/usr/bin/ssh", *ssh_options(cfg), str(cfg["backup"]["ssh_target"]), remote_command]


def ssh(
    cfg: dict[str, Any],
    remote_command: str,
    *,
    input_text: str | None = None,
    capture: bool = False,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    return run(
        ssh_command(cfg, remote_command),
        input_text=input_text,
        capture=capture,
        timeout=timeout,
    )


def effective_ssh_config(target: str) -> dict[str, str]:
    proc = run(["/usr/bin/ssh", "-G", target], capture=True, timeout=15)
    parsed: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key and value and key not in parsed:
            parsed[key] = value.strip()
    return parsed


def command_exists(command: str) -> bool:
    return subprocess.run(["/usr/bin/sh", "-c", f"command -v {shlex.quote(command)} >/dev/null 2>&1"]).returncode == 0


def mariadb_query(sql: str, *, database: str | None = None) -> list[list[str]]:
    args = ["/usr/bin/mariadb", "--protocol=socket", "--batch", "--skip-column-names"]
    if database:
        args.extend(["--database", database])
    args.extend(["--execute", sql])
    proc = run(args, capture=True, timeout=120)
    return [line.split("\t") for line in proc.stdout.splitlines() if line]


def preflight(cfg: dict[str, Any]) -> dict[str, Any]:
    backup = cfg["backup"]
    legacy_mariadb_enabled = bool(backup.get("mariadb_enabled", True))
    mariadb_databases_enabled = bool(backup.get("mariadb_databases_enabled", legacy_mariadb_enabled))
    mariadb_users_enabled = bool(backup.get("mariadb_users_enabled", legacy_mariadb_enabled))
    mariadb_enabled = mariadb_databases_enabled or mariadb_users_enabled
    required = ["rsync", "ssh", "zstd", "du"]
    if any(item["mode"] == "tar" for item in configured_backup_paths(cfg)):
        required.append("tar")
    if mariadb_enabled:
        required.extend(["mariadb", "mariadb-dump"])
    missing = [name for name in required if not command_exists(name)]
    if missing:
        raise RuntimeError("fehlende Programme: " + ", ".join(missing))

    actual_source = socket.getfqdn()
    expected_source = str(backup["expected_source_hostname"])
    if actual_source != expected_source:
        raise RuntimeError(f"Quellhostname geaendert: {actual_source!r}, erwartet {expected_source!r}")

    target = str(backup["ssh_target"])
    effective = effective_ssh_config(target)
    expected_values = {
        "hostname": str(backup["expected_ssh_hostname"]),
        "user": str(backup["expected_ssh_user"]),
        "port": str(backup["expected_ssh_port"]),
    }
    for key, expected in expected_values.items():
        actual = effective.get(key)
        if actual != expected:
            raise RuntimeError(f"SSH-Alias {target!r}: {key}={actual!r}, erwartet {expected!r}")

    probe = ssh(cfg, "hostname; pwd; df -PB1 . | tail -n 1", capture=True, timeout=60)
    lines = probe.stdout.splitlines()
    if len(lines) < 3:
        raise RuntimeError("ungueltige Antwort beim SSH-Preflight")
    remote_hostname, remote_home = lines[0].strip(), lines[1].strip()
    if remote_hostname != str(backup["expected_remote_hostname"]):
        raise RuntimeError(
            f"falscher SSH-Zielhost: {remote_hostname!r}, erwartet {backup['expected_remote_hostname']!r}"
        )
    if remote_home != str(backup["expected_remote_home"]):
        raise RuntimeError(f"falsches Remote-Home: {remote_home!r}, erwartet {backup['expected_remote_home']!r}")
    try:
        available_bytes = int(lines[2].split()[3])
    except (IndexError, ValueError) as exc:
        raise RuntimeError("freier Zielspeicher konnte nicht ermittelt werden") from exc
    minimum_free = int(backup.get("min_remote_free_bytes", 20 * 1024**3))
    version = mariadb_query("SELECT VERSION()") if mariadb_enabled else [["deaktiviert"]]
    if mariadb_enabled and not version:
        raise RuntimeError("lokale MariaDB ist nicht per Unix-Socket erreichbar")
    source_estimated_bytes = 0
    for item in configured_backup_paths(cfg):
        source = item["source_path"]
        proc = run(["/usr/bin/du", "-sb", "--", source], capture=True, timeout=900)
        source_estimated_bytes += int(proc.stdout.split()[0])
    database_estimated_bytes = 0
    if mariadb_databases_enabled:
        db_size_rows = mariadb_query(
            "SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables "
            "WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys')"
        )
        database_estimated_bytes = int(db_size_rows[0][0])
    estimated_upper_bound = source_estimated_bytes + database_estimated_bytes
    required_free = minimum_free + estimated_upper_bound
    if available_bytes < required_free:
        raise RuntimeError(
            f"zu wenig freier Zielspeicher: {format_size(available_bytes)} vorhanden, "
            f"mindestens {format_size(required_free)} fuer Worst-Case-Backup plus Reserve erforderlich"
        )
    LOG.info(
        "Preflight OK: source=%s target=%s@%s:%s remote_home=%s free=%s estimated=%s reserve=%s mariadb=%s",
        actual_source,
        expected_values["user"],
        expected_values["hostname"],
        expected_values["port"],
        remote_home,
        format_size(available_bytes),
        format_size(estimated_upper_bound),
        format_size(minimum_free),
        version[0][0],
    )
    return {
        "remote_home": remote_home,
        "available_bytes": available_bytes,
        "estimated_upper_bound": estimated_upper_bound,
        "mariadb_version": version[0][0],
        "mariadb_enabled": mariadb_enabled,
        "mariadb_databases_enabled": mariadb_databases_enabled,
        "mariadb_users_enabled": mariadb_users_enabled,
    }


def post_status(cfg: dict[str, Any], event: str, payload: dict[str, Any]) -> bool:
    status_cfg = cfg.get("status", {})
    if not bool(status_cfg.get("enabled", False)):
        return False
    endpoint = str(status_cfg.get("endpoint", "")).strip()
    token = str(status_cfg.get("token", "")).strip()
    if not endpoint or not token:
        LOG.warning("Status-Reporting aktiviert, aber endpoint/token fehlt")
        return False
    enriched_payload = dict(payload)
    if CURRENT_COMMAND_ID is not None:
        enriched_payload.setdefault("command_id", CURRENT_COMMAND_ID)
    body = json.dumps({"event": event, "payload": enriched_payload}, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=float(status_cfg.get("timeout_seconds", 15))) as response:
            if response.status >= 300:
                raise RuntimeError(f"HTTP {response.status}")
        return True
    except Exception as exc:
        LOG.warning("Status-Reporting (%s) fehlgeschlagen: %s", event, exc)
        return False


def status_api_post(cfg: dict[str, Any], endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
    status_cfg = cfg.get("status", {})
    token = str(status_cfg.get("token", "")).strip()
    if not endpoint or not token:
        raise RuntimeError("Portal-Endpoint oder Agent-Token fehlt")
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=float(status_cfg.get("timeout_seconds", 15))) as response:
        if response.status >= 300:
            raise RuntimeError(f"Portal antwortet mit HTTP {response.status}")
        return json.loads(response.read().decode("utf-8"))


def apply_config_update(cfg: dict[str, Any], config_path: str, update: dict[str, Any]) -> None:
    try:
        expected_version = int(update["version"])
        decoded = base64.b64decode(str(update["content_b64"]), validate=True)
        parsed = tomllib.loads(decoded.decode("utf-8"))
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise RuntimeError("Portal lieferte eine ungueltige Agent-Konfiguration") from exc
    if int(parsed.get("backup", {}).get("config_version", -1)) != expected_version:
        raise RuntimeError("Versionsnummer der Portal-Konfiguration ist inkonsistent")
    write_private_file(Path(config_path), decoded, 0o600)
    cfg.clear()
    cfg.update(parsed)
    LOG.info("Agent-Konfiguration auf Portal-Version %s aktualisiert", expected_version)


def script_path() -> Path:
    return Path(__file__).resolve()


def script_digest() -> str:
    return hashlib.sha256(script_path().read_bytes()).hexdigest()


def write_private_file(path: Path, payload: bytes, mode: int) -> None:
    """Replace a file atomically without ever following a symlink."""
    if path.is_symlink():
        raise RuntimeError(f"Datei darf kein Symlink sein: {path}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.raven-{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def apply_script_update(update: dict[str, Any]) -> None:
    """Store a newer agent script; the next scheduled run executes it."""
    try:
        expected_digest = str(update["sha256"]).strip().lower()
        decoded = base64.b64decode(str(update["content_b64"]), validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("Portal lieferte ein ungueltiges Agent-Skript") from exc
    if hashlib.sha256(decoded).hexdigest() != expected_digest:
        raise RuntimeError("Pruefsumme des ausgelieferten Agent-Skripts stimmt nicht")
    if not decoded.startswith(b"#!"):
        raise RuntimeError("Ausgeliefertes Agent-Skript hat keinen Interpreter-Header")
    write_private_file(script_path(), decoded, 0o700)
    LOG.info("Agent-Skript auf Portal-Version %s aktualisiert; gilt ab dem naechsten Lauf", expected_digest[:12])


def state_file(cfg: dict[str, Any]) -> Path:
    return Path(str(cfg.get("backup", {}).get("state_path", DEFAULT_STATE_PATH)))


def load_agent_state(cfg: dict[str, Any]) -> dict[str, Any]:
    try:
        state = json.loads(state_file(cfg).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def record_successful_backup(cfg: dict[str, Any], report: dict[str, Any]) -> None:
    """Remember the last success locally so the agent can judge the interval itself."""
    state = load_agent_state(cfg)
    state.update(
        {
            "last_success_at": str(report.get("finished_at") or datetime.now().astimezone().isoformat()),
            "last_run_id": str(report.get("run_id", "")),
            "policy_id": report.get("policy", {}).get("id"),
        }
    )
    try:
        write_private_file(state_file(cfg), json.dumps(state, ensure_ascii=False).encode("utf-8"), 0o600)
    except (OSError, RuntimeError) as exc:
        LOG.warning("Lokaler Backup-Zustand konnte nicht gespeichert werden: %s", exc)


def parsed_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.astimezone()


def last_known_success(cfg: dict[str, Any], portal_schedule: dict[str, Any] | None) -> datetime | None:
    """Return the most recent successful backup known locally or reported by the portal."""
    candidates = [parsed_time(load_agent_state(cfg).get("last_success_at"))]
    if portal_schedule:
        candidates.append(parsed_time(portal_schedule.get("last_success_at")))
    known = [item for item in candidates if item]
    return max(known) if known else None


def interval_hours(cfg: dict[str, Any], portal_schedule: dict[str, Any] | None) -> int:
    source = portal_schedule if portal_schedule else cfg.get("schedule", {})
    try:
        hours = int(source.get("interval_hours", DEFAULT_INTERVAL_HOURS))
    except (TypeError, ValueError):
        hours = DEFAULT_INTERVAL_HOURS
    return hours if hours > 0 else DEFAULT_INTERVAL_HOURS


def backup_due(cfg: dict[str, Any], portal_schedule: dict[str, Any] | None) -> tuple[bool, str]:
    """Decide whether the configured interval has elapsed since the last success.

    The portal delivers the currently open slot with every poll, so a changed
    policy takes effect immediately. Without a portal answer the agent falls
    back to the interval of its own configuration.
    """
    last_success = last_known_success(cfg, portal_schedule)
    hours = interval_hours(cfg, portal_schedule)
    if last_success is None:
        return True, "noch kein erfolgreiches Backup vorhanden"
    current_slot = parsed_time((portal_schedule or {}).get("current_slot"))
    if current_slot is None:
        current_slot = datetime.now().astimezone() - timedelta(hours=hours)
        if last_success > current_slot:
            return False, (
                f"letztes erfolgreiches Backup {last_success.isoformat()} liegt weniger als "
                f"{hours} Stunden zurueck"
            )
        return True, f"letztes erfolgreiches Backup {last_success.isoformat()} ist aelter als {hours} Stunden"
    if last_success >= current_slot:
        next_due = (portal_schedule or {}).get("next_slot") or "unbekannt"
        return False, (
            f"Termin {current_slot.isoformat()} ist durch das Backup vom {last_success.isoformat()} "
            f"bereits erfuellt; naechster Termin {next_due}"
        )
    return True, f"Termin {current_slot.isoformat()} ist offen"


def poll_portal(cfg: dict[str, Any], config_path: str) -> dict[str, Any]:
    """Ask the portal for the live schedule, pending orders and agent updates."""
    status_cfg = cfg.get("status", {})
    if not bool(status_cfg.get("enabled", False)):
        raise RuntimeError("Zentrale Steuerung ist in [status] deaktiviert")
    endpoint = str(status_cfg.get("poll_endpoint", "")).strip()
    result = status_api_post(
        cfg,
        endpoint,
        {
            "hostname": socket.getfqdn(),
            "time": datetime.now(timezone.utc).isoformat(),
            "config_version": int(cfg["backup"].get("config_version", 0)),
            "mariadb_available": bool(cfg["backup"].get("mariadb_available", False)),
            "script_sha256": script_digest(),
        },
    )
    if isinstance(result.get("config_update"), dict):
        apply_config_update(cfg, config_path, result["config_update"])
    if isinstance(result.get("script_update"), dict):
        try:
            apply_script_update(result["script_update"])
        except (OSError, RuntimeError) as exc:
            LOG.warning("Agent-Skript konnte nicht aktualisiert werden: %s", exc)
    if result.get("action") not in {"none", "backup"}:
        raise RuntimeError("Portal lieferte eine unbekannte Anweisung")
    if result.get("action") == "backup" and not isinstance(result.get("command_id"), int):
        raise RuntimeError("Portal lieferte einen ungueltigen Backup-Auftrag")
    return result


def post_command_state(
    cfg: dict[str, Any], command_id: int, status: str, *, run_id: str | None = None, message: str = ""
) -> bool:
    endpoint_base = str(cfg.get("status", {}).get("command_endpoint", "")).rstrip("/")
    try:
        status_api_post(
            cfg,
            f"{endpoint_base}/{command_id}",
            {"status": status, "run_id": run_id, "message": message},
        )
        return True
    except Exception as exc:
        LOG.warning("Command-Status %s fuer Auftrag %s fehlgeschlagen: %s", status, command_id, exc)
        return False


def compact_portal_report(report: dict[str, Any] | None, error: BaseException | None) -> dict[str, Any]:
    if report:
        mariadb = dict(report.get("mariadb", {}))
        mariadb.pop("databases", None)
        return {
            "status": report.get("status"),
            "run_id": report.get("run_id"),
            "duration_seconds": report.get("duration_seconds"),
            "logical_run_bytes": report.get("logical_run_bytes"),
            "protected_logical_bytes": report.get("protected_logical_bytes"),
            "previous_successful_backup": report.get("previous_successful_backup"),
            "policy": report.get("policy"),
            "classifications": report.get("classifications"),
            "filesystem": report.get("filesystem"),
            "mariadb": mariadb,
        }
    if error:
        return {
            "status": "failure",
            "error_type": type(error).__name__,
            "error": str(error),
            "phase": CURRENT_PHASE,
        }
    return {}


def upload_agent_log(
    cfg: dict[str, Any], status: str, report: dict[str, Any] | None, error: BaseException | None
) -> bool:
    log_cfg = cfg.get("logging", {})
    if not bool(log_cfg.get("portal_enabled", False)) or PORTAL_LOG_HANDLER is None:
        return False
    endpoint = str(cfg.get("status", {}).get("log_endpoint", "")).strip()
    if not endpoint:
        LOG.warning("Portal-Logging aktiviert, aber log_endpoint fehlt")
        return False
    log_text, truncated = PORTAL_LOG_HANDLER.snapshot()
    payload = {
        "upload_id": LOG_UPLOAD_ID,
        "run_id": CURRENT_RUN_ID,
        "command_id": CURRENT_COMMAND_ID,
        "status": status,
        "source_hostname": socket.getfqdn(),
        "phase": CURRENT_PHASE,
        "started_at": ATTEMPT_STARTED_AT,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "log_level": str(log_cfg.get("level", "INFO")).upper(),
        "log_text": log_text,
        "truncated": truncated,
        "report": compact_portal_report(report, error),
    }
    try:
        status_api_post(cfg, endpoint, payload)
        return True
    except Exception as exc:
        LOG.warning("Dauerhaftes Agentenlog konnte nicht an das Portal gesendet werden: %s", exc)
        return False


def acquire_local_lock(cfg: dict[str, Any]) -> Any | None:
    path = str(cfg["backup"].get("local_lock_path", "/run/raven-backup-agent.lock"))
    handle = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()) + "\n")
    handle.flush()
    return handle


def retry(operation_name: str, attempts: int, function: Any) -> Any:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return function()
        except Exception as exc:
            last_error = exc
            LOG.warning("%s fehlgeschlagen (Versuch %d/%d): %s", operation_name, attempt, attempts, exc)
            if attempt < attempts:
                time.sleep(min(30, 5 * attempt))
    raise RuntimeError(f"{operation_name} nach {attempts} Versuchen fehlgeschlagen: {last_error}")


def stream_compressed(
    cfg: dict[str, Any], producer: list[str], remote_file: str, *, attempts: int
) -> None:
    compression_level = int(cfg["backup"].get("zstd_level", 3))
    remote_tmp = remote_file + ".partial"
    remote_write = (
        f"umask 077; mkdir -p {shlex.quote(str(Path(remote_file).parent))}; "
        f"cat > {shlex.quote(remote_tmp)} && mv -f {shlex.quote(remote_tmp)} {shlex.quote(remote_file)}"
    )
    pipeline = (
        f"{shlex.join(producer)} | /usr/bin/zstd -q -T0 -{compression_level} | "
        f"{shlex.join(ssh_command(cfg, remote_write))}"
    )

    def attempt() -> None:
        proc = subprocess.run(["/usr/bin/bash", "-o", "pipefail", "-c", pipeline], check=False)
        if proc.returncode != 0:
            ssh(
                cfg,
                f"rm -f -- {shlex.quote(remote_tmp)} {shlex.quote(remote_file)}",
                timeout=60,
            )
            raise RuntimeError(f"Streaming-Pipeline endete mit Status {proc.returncode}")

    retry(f"Stream {remote_file}", attempts, attempt)


def remote_file_size(cfg: dict[str, Any], remote_file: str) -> int:
    proc = ssh(cfg, f"stat -c %s -- {shlex.quote(remote_file)}", capture=True, timeout=60)
    return int(proc.stdout.strip())


def database_inventory() -> tuple[list[str], dict[str, int]]:
    databases = [row[0] for row in mariadb_query("SHOW DATABASES") if row[0] not in SYSTEM_DATABASES]
    sizes = {name: 0 for name in databases}
    rows = mariadb_query(
        "SELECT table_schema,COALESCE(SUM(data_length+index_length),0) "
        "FROM information_schema.tables "
        "WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys') "
        "GROUP BY table_schema"
    )
    for name, value in rows:
        if name in sizes:
            sizes[name] = int(value)
    return sorted(databases), sizes


def dump_schema(cfg: dict[str, Any], db: str, db_dir: str, attempts: int) -> int:
    producer = [
        "/usr/bin/mariadb-dump", "--protocol=socket", "--skip-comments", "--hex-blob",
        "--routines", "--events", "--triggers", "--no-data", "--databases", db,
    ]
    destination = f"{db_dir}/schema.sql.zst"
    stream_compressed(cfg, producer, destination, attempts=attempts)
    return remote_file_size(cfg, destination)


def dump_database_data(cfg: dict[str, Any], db: str, db_dir: str, attempts: int) -> int:
    producer = [
        "/usr/bin/mariadb-dump", "--protocol=socket", "--skip-comments", "--hex-blob",
        "--single-transaction", "--quick", "--no-create-info", "--skip-triggers", "--databases", db,
    ]
    destination = f"{db_dir}/data.sql.zst"
    stream_compressed(cfg, producer, destination, attempts=attempts)
    return remote_file_size(cfg, destination)


def dump_database_by_table(cfg: dict[str, Any], db: str, db_dir: str, attempts: int) -> tuple[int, int]:
    rows = mariadb_query("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'", database=db)
    table_count = 0
    compressed_bytes = 0
    for row in rows:
        table = row[0]
        safe_name = quote(table, safe="._-")
        destination = f"{db_dir}/tables/{safe_name}.sql.zst"
        producer = [
            "/usr/bin/mariadb-dump", "--protocol=socket", "--skip-comments", "--hex-blob",
            "--single-transaction", "--quick", "--no-create-info", "--skip-triggers", db, table,
        ]
        stream_compressed(cfg, producer, destination, attempts=attempts)
        compressed_bytes += remote_file_size(cfg, destination)
        table_count += 1
    return table_count, compressed_bytes


def backup_databases(cfg: dict[str, Any], run_dir: str) -> dict[str, Any]:
    backup = cfg["backup"]
    attempts = int(backup.get("stream_attempts", 2))
    split_threshold = int(backup.get("database_split_threshold_bytes", 2 * 1024**3))
    legacy_enabled = bool(backup.get("mariadb_enabled", True))
    databases_enabled = bool(backup.get("mariadb_databases_enabled", legacy_enabled))
    users_enabled = bool(backup.get("mariadb_users_enabled", legacy_enabled))
    databases, sizes = database_inventory() if databases_enabled else ([], {})
    report: dict[str, Any] = {
        "databases_enabled": databases_enabled,
        "users_enabled": users_enabled,
        "database_count": len(databases),
        "estimated_bytes": sum(sizes.values()),
        "compressed_bytes": 0,
        "schema_compressed_bytes": 0,
        "data_compressed_bytes": 0,
        "data_file_count": 0,
        "split_database_count": 0,
        "users_and_grants_bytes": 0,
        "users_and_grants_statements": 0,
        "databases": {},
    }

    if users_enabled:
        users_file = f"{run_dir}/database/system/users-and-grants.sql.zst"
        stream_compressed(
            cfg,
            ["/usr/bin/mariadb-dump", "--protocol=socket", "--skip-comments", "--system=users"],
            users_file,
            attempts=attempts,
        )
        users_size = remote_file_size(cfg, users_file)
        report["compressed_bytes"] += users_size
        report["users_and_grants_bytes"] = users_size
        statement_proc = ssh(
            cfg,
            f"zstdcat {shlex.quote(users_file)} | awk '/^(CREATE USER|GRANT)/ {{count++}} END {{print count+0}}'",
            capture=True,
            timeout=60,
        )
        report["users_and_grants_statements"] = int(statement_proc.stdout.strip())

    for index, db in enumerate(databases, start=1):
        safe_db = quote(db, safe="._-")
        db_dir = f"{run_dir}/database/{safe_db}"
        estimated = sizes.get(db, 0)
        LOG.info("MariaDB %d/%d: %s (%s geschaetzt)", index, len(databases), db, format_size(estimated))
        schema_bytes = dump_schema(cfg, db, db_dir, attempts)
        mode = "single-file"
        table_count: int | None = None
        try:
            if estimated > split_threshold:
                raise OverflowError(
                    f"Datenbankgroesse {format_size(estimated)} ueber Split-Schwelle {format_size(split_threshold)}"
                )
            data_bytes = dump_database_data(cfg, db, db_dir, attempts)
        except Exception as exc:
            LOG.warning("%s: Wechsel auf Tabellen-Fallback: %s", db, exc)
            ssh(cfg, f"rm -f -- {shlex.quote(db_dir + '/data.sql.zst')} {shlex.quote(db_dir + '/data.sql.zst.partial')}")
            table_count, data_bytes = dump_database_by_table(cfg, db, db_dir, attempts)
            mode = "per-table"
        report["compressed_bytes"] += schema_bytes + data_bytes
        report["schema_compressed_bytes"] += schema_bytes
        report["data_compressed_bytes"] += data_bytes
        report["data_file_count"] += table_count if table_count is not None else 1
        if mode == "per-table":
            report["split_database_count"] += 1
        report["databases"][db] = {
            "estimated_bytes": estimated,
            "schema_bytes": schema_bytes,
            "data_bytes": data_bytes,
            "mode": mode,
            "table_count": table_count,
        }
    return report


def find_previous_backup(cfg: dict[str, Any], remote_home: str) -> str | None:
    command = (
        f"find {shlex.quote(remote_home)} -mindepth 2 -maxdepth 2 -type f -name .backup-ok "
        "-printf '%h\\n' | sort | tail -n 1"
    )
    proc = ssh(cfg, command, capture=True, timeout=60)
    value = proc.stdout.strip()
    return value or None


def rsync_source(
    cfg: dict[str, Any], source: str, destination: str, previous: str | None, attempts: int
) -> None:
    ssh_transport = shlex.join(["/usr/bin/ssh", *ssh_options(cfg)])
    args = [
        "/usr/bin/rsync", "-aHAXz", "--numeric-ids", "--delete", "--delete-delay",
        "--partial", "--partial-dir=.rsync-partial", "--human-readable", "--stats",
        "--rsync-path=/usr/bin/rsync --fake-super",
        "-e", ssh_transport,
    ]
    if previous:
        args.append(f"--link-dest={previous}")
    args.extend([source.rstrip("/") + "/", f"{cfg['backup']['ssh_target']}:{destination.rstrip('/')}/"])
    retry(f"rsync {source}", attempts, lambda: run(args))


def backup_filesystems(
    cfg: dict[str, Any], remote_home: str, run_dir: str, previous_run: str | None
) -> dict[str, Any]:
    backup = cfg["backup"]
    attempts = int(backup.get("rsync_attempts", 3))
    report: dict[str, Any] = {"sources": {}}
    for item in configured_backup_paths(cfg):
        source = item["source_path"]
        name = item["target_name"]
        mode = item["mode"]
        if not Path(source).is_dir():
            raise RuntimeError(f"Backupquelle fehlt oder ist kein Ordner: {source}")
        logical_proc = run(["/usr/bin/du", "-sb", "--", source], capture=True, timeout=900)
        logical_bytes = int(logical_proc.stdout.split()[0])
        if mode == "sync":
            destination = f"{remote_home}/current/{name}"
            LOG.info("Current-Sync %s -> %s", source, destination)
            ssh(cfg, f"umask 077; mkdir -p {shlex.quote(destination)}", timeout=60)
            rsync_source(cfg, source, destination, None, attempts)
            size_proc = ssh(cfg, f"du -sb -- {shlex.quote(destination)}", capture=True, timeout=600)
            stored_bytes = int(size_proc.stdout.split()[0])
        else:
            destination = f"{run_dir}/filesystem/{name}.tar.zst"
            parent = str(Path(source).parent)
            leaf = Path(source).name
            LOG.info("Persistentes Tar.Zstd %s -> %s", source, destination)
            stream_compressed(
                cfg,
                ["/usr/bin/tar", "--acls", "--xattrs", "--numeric-owner", "-C", parent, "-cf", "-", leaf],
                destination,
                attempts=attempts,
            )
            stored_bytes = remote_file_size(cfg, destination)
        report["sources"][source] = {
            "target_name": name,
            "mode": mode,
            "destination": destination,
            "logical_bytes": logical_bytes,
            "stored_bytes": stored_bytes,
            "persistent": mode != "sync",
        }
    return report


def write_remote_json(cfg: dict[str, Any], remote_file: str, payload: dict[str, Any]) -> None:
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n"
    temp = remote_file + ".partial"
    command = (
        f"umask 077; cat > {shlex.quote(temp)} && mv -f {shlex.quote(temp)} {shlex.quote(remote_file)}"
    )
    ssh(cfg, command, input_text=serialized, timeout=60)


def append_remote_log(cfg: dict[str, Any], remote_file: str, payload: dict[str, Any]) -> None:
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n"
    ssh(cfg, f"umask 077; cat >> {shlex.quote(remote_file)}", input_text=serialized, timeout=60)


def send_mail(
    cfg: dict[str, Any],
    subject: str,
    title: str,
    body: str,
    *,
    success: bool,
    report_rows: list[tuple[str, str]] | None = None,
) -> None:
    smtp = cfg["smtp"]
    recipients_raw = smtp.get("to", [])
    recipients = [recipients_raw] if isinstance(recipients_raw, str) else list(recipients_raw)
    recipients = [str(value).strip() for value in recipients if str(value).strip()]
    if not recipients:
        raise ValueError("smtp.to enthaelt keine Empfaengeradresse")
    message = EmailMessage()
    message["From"] = str(smtp["from_address"])
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(f"{title}\n\n{body}\n")
    color = "#137333" if success else "#b3261e"
    escaped_body = html.escape(body).replace("\n", "<br>")
    rows_html = ""
    if report_rows:
        rows_html = "<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;margin-top:20px;\">"
        for label, value in report_rows:
            rows_html += (
                "<tr>"
                f'<th style="text-align:left;padding:9px;border-bottom:1px solid #ddd;background:#f5f7f9;">{html.escape(label)}</th>'
                f'<td style="padding:9px;border-bottom:1px solid #ddd;">{html.escape(value)}</td>'
                "</tr>"
            )
        rows_html += "</table>"
    message.add_alternative(
        f"""<!doctype html><html lang="de"><body style="font-family:Arial,sans-serif;background:#f5f7f9;padding:24px;">
<div style="max-width:800px;margin:auto;background:#fff;border:1px solid #dfe3e7;border-radius:8px;overflow:hidden;">
<div style="background:{color};color:white;padding:20px 24px;"><h1 style="margin:0;font-size:22px;">{html.escape(title)}</h1></div>
<div style="padding:24px;line-height:1.5;">{escaped_body}{rows_html}</div></div></body></html>""",
        subtype="html",
    )
    with smtplib.SMTP(str(smtp["host"]), int(smtp["port"]), timeout=float(smtp.get("timeout_seconds", 20))) as client:
        client.ehlo()
        client.login(str(smtp["username"]), str(smtp["password"]))
        client.send_message(message, to_addrs=recipients)


def notifications_enabled(cfg: dict[str, Any], event: str) -> bool:
    notifications = cfg.get("notifications", {})
    if event == "success":
        return bool(notifications.get("mail_on_success", cfg["backup"].get("notify_on_success", False)))
    if event == "failure":
        return bool(notifications.get("mail_on_failure", True))
    raise ValueError(f"unbekannter Benachrichtigungstyp: {event}")


def execute_backup(cfg: dict[str, Any], force_success_mail: bool) -> dict[str, Any]:
    global CURRENT_PHASE, CURRENT_RUN_ID
    backup = cfg["backup"]
    started = datetime.now().astimezone()
    run_id = started.strftime("%Y%m%d%H%M%S") + f"{started.microsecond // 1000:03d}"
    CURRENT_RUN_ID = run_id
    CURRENT_PHASE = "preflight"
    preflight_result = preflight(cfg)
    remote_home = preflight_result["remote_home"]
    run_dir = f"{remote_home}/{run_id}"
    ssh(cfg, f"umask 077; mkdir -p {shlex.quote(run_dir)}", timeout=60)
    previous = find_previous_backup(cfg, remote_home)
    LOG.info("Backup %s gestartet; vorheriger erfolgreicher Lauf: %s", run_id, previous or "keiner")
    post_status(
        cfg,
        "started",
        {
            "run_id": run_id,
            "command_id": CURRENT_COMMAND_ID,
            "started_at": started.isoformat(),
            "phase": "started",
            "previous": previous,
        },
    )

    CURRENT_PHASE = "mariadb"
    if preflight_result["mariadb_enabled"]:
        db_report = backup_databases(cfg, run_dir)
    else:
        db_report = {
            "database_count": 0,
            "estimated_bytes": 0,
            "compressed_bytes": 0,
            "schema_compressed_bytes": 0,
            "data_compressed_bytes": 0,
            "data_file_count": 0,
            "split_database_count": 0,
            "users_and_grants_bytes": 0,
            "users_and_grants_statements": 0,
            "databases": {},
            "databases_enabled": False,
            "users_enabled": False,
            "disabled": True,
        }
    CURRENT_PHASE = "filesystem"
    fs_report = backup_filesystems(cfg, remote_home, run_dir, previous)
    CURRENT_PHASE = "finalize"
    size_proc = ssh(cfg, f"du -sb -- {shlex.quote(run_dir)}", capture=True, timeout=1800)
    run_bytes = int(size_proc.stdout.split()[0])
    finished = datetime.now().astimezone()
    classifications: dict[str, Any] = {}
    for source, source_report in fs_report["sources"].items():
        target_name = source_report["target_name"]
        classifications[f"filesystem_{target_name}"] = {
            "label": f"Dateisystem {source}",
            "kind": "filesystem",
            "mode": source_report["mode"],
            "persistent": source_report["persistent"],
            "logical_bytes": source_report["logical_bytes"],
            "stored_bytes": source_report["stored_bytes"],
            "destination": source_report["destination"],
        }
    classifications.update({
        "mariadb_users": {
            "label": "MariaDB Benutzer und Rechte",
            "kind": "mariadb-users",
            "enabled": db_report["users_enabled"],
            "compressed_bytes": db_report["users_and_grants_bytes"],
            "statement_count": db_report["users_and_grants_statements"],
        },
        "mariadb_schemas": {
            "label": "MariaDB Schemas",
            "kind": "mariadb-schema",
            "enabled": db_report["databases_enabled"],
            "compressed_bytes": db_report["schema_compressed_bytes"],
            "file_count": db_report["database_count"],
        },
        "mariadb_data": {
            "label": "MariaDB Daten",
            "kind": "mariadb-data",
            "enabled": db_report["databases_enabled"],
            "estimated_bytes": db_report["estimated_bytes"],
            "compressed_bytes": db_report["data_compressed_bytes"],
            "file_count": db_report["data_file_count"],
            "split_database_count": db_report["split_database_count"],
        },
    })
    report = {
        "status": "ok",
        "run_id": run_id,
        "source_hostname": socket.getfqdn(),
        "target_hostname": str(cfg["backup"]["expected_remote_hostname"]),
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_seconds": round((finished - started).total_seconds(), 3),
        "logical_run_bytes": run_bytes,
        "protected_logical_bytes": sum(
            int(item["logical_bytes"]) for item in fs_report["sources"].values()
        ) + int(db_report["estimated_bytes"]),
        "previous_successful_backup": previous,
        "policy": {
            "id": backup.get("policy_id"),
            "name": backup.get("policy_name", "Legacy"),
            "paths": configured_backup_paths(cfg),
        },
        "mariadb": db_report,
        "filesystem": fs_report,
        "classifications": classifications,
    }
    if CURRENT_COMMAND_ID is not None:
        report["command_id"] = CURRENT_COMMAND_ID
    write_remote_json(cfg, f"{run_dir}/manifest.json", report)
    append_remote_log(cfg, f"{run_dir}/backup.log", report)
    write_remote_json(cfg, f"{run_dir}/.backup-ok", report)
    record_successful_backup(cfg, report)
    post_status(cfg, "success", report)
    LOG.info(
        "BACKUP OK: run=%s duration=%.3fs volume=%s",
        run_id,
        report["duration_seconds"],
        format_size(run_bytes),
    )

    notify_success = notifications_enabled(cfg, "success") or force_success_mail
    if notify_success:
        users_size = classifications["mariadb_users"]["compressed_bytes"]
        schema_size = classifications["mariadb_schemas"]["compressed_bytes"]
        data_size = classifications["mariadb_data"]["compressed_bytes"]
        body = (
            f"Quelle: {report['source_hostname']}\nZiel: {report['target_hostname']}\n"
            f"Backup-ID: {run_id}\nDauer: {report['duration_seconds']} Sekunden\n"
            f"Persistentes Laufvolumen: {format_size(run_bytes)}\n"
            f"Geschuetztes logisches Volumen: {format_size(report['protected_logical_bytes'])}\n"
            f"Datenbanken: {db_report['database_count']}"
        )
        rows: list[tuple[str, str]] = [
            ("Status", "Erfolgreich"),
            ("Backup-ID", run_id),
            ("Quelle", report["source_hostname"]),
            ("Ziel", report["target_hostname"]),
            ("Dauer", f"{report['duration_seconds']:.3f} Sekunden"),
            ("Persistentes Laufvolumen", format_size(run_bytes)),
            ("Geschuetztes logisches Volumen", format_size(report["protected_logical_bytes"])),
            ("Backup-Policy", str(report["policy"]["name"])),
        ]
        for source, source_report in fs_report["sources"].items():
            rows.append(
                (
                    f"Dateisystem {source}",
                    f"{format_size(source_report['logical_bytes'])} logisch, "
                    f"{format_size(source_report['stored_bytes'])} gespeichert, Modus {source_report['mode']}",
                )
            )
        rows.extend([
            (
                "MariaDB Benutzer und Rechte",
                (f"{format_size(users_size)}, {db_report['users_and_grants_statements']} CREATE USER/GRANT-Anweisungen"
                 if db_report["users_enabled"] else "durch Policy deaktiviert"),
            ),
            ("MariaDB Schemas", (f"{format_size(schema_size)}, {db_report['database_count']} Dateien"
                                 if db_report["databases_enabled"] else "durch Policy deaktiviert")),
            (
                "MariaDB Daten",
                (f"{format_size(data_size)} komprimiert, {format_size(db_report['estimated_bytes'])} geschaetzt, "
                 f"{db_report['data_file_count']} Dateien" if db_report["databases_enabled"]
                 else "durch Policy deaktiviert"),
            ),
            ("Tabellen-Fallback", f"{db_report['split_database_count']} Datenbanken"),
            ("Vorheriges Backup", previous or "keines"),
        ])
        try:
            send_mail(
                cfg,
                f"[Backup-OK] {socket.getfqdn()} {run_id}",
                "Backup erfolgreich",
                body,
                success=True,
                report_rows=rows,
            )
        except Exception:
            LOG.exception("Erfolgsmail konnte nicht gesendet werden")
    return report


def main() -> int:
    global CURRENT_COMMAND_ID, ATTEMPT_STARTED_AT
    args = parse_args()
    cfg: dict[str, Any] | None = None
    attempted = False
    final_report: dict[str, Any] | None = None
    final_error: BaseException | None = None
    try:
        cfg = load_config(args.config)
        setup_logging(cfg)
        if args.test_email:
            send_mail(
                cfg,
                f"[Backup-Test] {socket.getfqdn()}",
                "Backup-Mailtest erfolgreich",
                f"Quelle: {socket.getfqdn()}\nZeit: {datetime.now(timezone.utc).isoformat()}",
                success=True,
            )
            LOG.info("Testmail versendet")
            return 0
        if args.preflight_only:
            preflight(cfg)
            return 0
        if args.check_status:
            if not post_status(
                cfg,
                "heartbeat",
                {"time": datetime.now(timezone.utc).isoformat(), "hostname": socket.getfqdn()},
            ):
                raise RuntimeError("Status-Heartbeat zum Backup-Portal fehlgeschlagen")
            LOG.info("Status-Heartbeat erfolgreich")
            return 0
        lock_handle = acquire_local_lock(cfg)
        if lock_handle is None:
            LOG.info("Backup-Agent ist bereits aktiv; dieser Aufruf wird uebersprungen")
            return 0 if args.poll else 3
        if args.poll:
            try:
                result = poll_portal(cfg, args.config)
            except Exception as exc:
                LOG.error("Portal-Polling fehlgeschlagen: %s", exc)
                return 2
            portal_schedule = result.get("schedule") if isinstance(result.get("schedule"), dict) else None
            if result.get("action") != "backup":
                return 0
            command = result
            CURRENT_COMMAND_ID = int(command["command_id"])
            forced = args.force or bool(command.get("force"))
            due, reason = backup_due(cfg, portal_schedule)
            if not due and not forced:
                LOG.info("Backup-Auftrag %s abgelehnt: %s", CURRENT_COMMAND_ID, reason)
                post_command_state(cfg, CURRENT_COMMAND_ID, "skipped", message=f"Intervall nicht abgelaufen: {reason}")
                return 0
            apply_command_policy(cfg, command)
            LOG.info(
                "Zentralen Backup-Auftrag %s uebernommen (Grund: %s, Policy: %s, %s)",
                CURRENT_COMMAND_ID,
                command.get("reason", "unbekannt"),
                cfg["backup"].get("policy_name", "Legacy"),
                "erzwungen" if forced and not due else reason,
            )
            post_command_state(
                cfg,
                CURRENT_COMMAND_ID,
                "running",
                message=f"Agent hat Auftrag mit Policy {cfg['backup'].get('policy_name', 'Legacy')} uebernommen",
            )
            attempted = True
            ATTEMPT_STARTED_AT = datetime.now(timezone.utc).isoformat()
            report = execute_backup(cfg, args.notify_success)
            final_report = report
            post_command_state(
                cfg,
                CURRENT_COMMAND_ID,
                "success",
                run_id=str(report["run_id"]),
                message=f"Backup erfolgreich, Volumen {format_size(int(report['logical_run_bytes']))}",
            )
            return 0
        due, reason = backup_due(cfg, None)
        if not due and not args.force:
            LOG.info("Backup uebersprungen: %s; mit --force laesst es sich trotzdem starten", reason)
            return 0
        attempted = True
        ATTEMPT_STARTED_AT = datetime.now(timezone.utc).isoformat()
        final_report = execute_backup(cfg, args.notify_success)
        return 0
    except Exception as exc:
        final_error = exc
        if not logging.getLogger().handlers:
            setup_logging(cfg)
        include_traceback = bool((cfg or {}).get("logging", {}).get("include_traceback", True))
        if include_traceback:
            LOG.exception("BACKUP FEHLGESCHLAGEN: %s", exc)
        else:
            LOG.error("BACKUP FEHLGESCHLAGEN: %s", exc)
        if cfg is not None and notifications_enabled(cfg, "failure"):
            body = (
                f"Quelle: {socket.getfqdn()}\nZeit: {datetime.now(timezone.utc).isoformat()}\n"
                f"Phase: {CURRENT_PHASE}\nFehler: {type(exc).__name__}: {exc}\n\nTraceback:\n{traceback.format_exc()}"
            )
            try:
                send_mail(
                    cfg,
                    f"[Backup-FEHLER] {socket.getfqdn()}",
                    "Backup fehlgeschlagen",
                    body,
                    success=False,
                    report_rows=[
                        ("Status", "Fehlgeschlagen"),
                        ("Quelle", socket.getfqdn()),
                        ("Phase", CURRENT_PHASE),
                        ("Fehlerklasse", type(exc).__name__),
                        ("Fehler", str(exc)),
                    ],
                )
            except Exception:
                LOG.exception("Fehlermail konnte nicht gesendet werden")
        if cfg is not None:
            if CURRENT_COMMAND_ID is not None:
                post_command_state(
                    cfg,
                    CURRENT_COMMAND_ID,
                    "failure",
                    run_id=CURRENT_RUN_ID,
                    message=f"{type(exc).__name__}: {exc}",
                )
            post_status(
                cfg,
                "failure",
                {
                    "run_id": CURRENT_RUN_ID,
                    "command_id": CURRENT_COMMAND_ID,
                    "phase": CURRENT_PHASE,
                    "time": datetime.now(timezone.utc).isoformat(),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
        return 2
    finally:
        if cfg is not None and attempted:
            upload_agent_log(cfg, "failure" if final_error else "success", final_report, final_error)


if __name__ == "__main__":
    raise SystemExit(main())
