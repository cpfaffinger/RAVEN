#!/usr/bin/env python3
from __future__ import annotations

import base64
from collections import OrderedDict
import copy
import hashlib
import hmac
import ipaddress
import json
import logging
import mimetypes
import os
import pwd
import re
import secrets
import sqlite3
import stat as statlib
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask

import backup_schedule
from domain_config import resolve_domain_config
from runtime_config import bootstrap_settings, effective_settings, runtime_config


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("BACKUP_PORTAL_CONFIG", "/etc/backup-portal/config.toml"))
with CONFIG_PATH.open("rb") as handle:
    CONFIG = tomllib.load(handle)

DB_PATH = Path(CONFIG["database"]["path"])
RUNTIME_CONFIG = runtime_config(CONFIG)
HOME_ROOT = Path(CONFIG["paths"].get("home_root", "/home"))
CHECKER_STATE = Path(CONFIG["paths"].get("checker_state", "/var/lib/backup-check/state.json"))
CHECKER_CONFIG_SECTION = CONFIG.get("checker", {})
CHECKER_SCRIPT = Path(CHECKER_CONFIG_SECTION.get("script", "/opt/backup-portal/checker/backup_check.py"))
CHECKER_CONFIG_PATH = Path(CHECKER_CONFIG_SECTION.get("config", "/etc/backup-portal/backup-check.toml"))
DOMAIN_CONFIG = resolve_domain_config(RUNTIME_CONFIG)
PORTAL_FQDN = str(DOMAIN_CONFIG["fqdn"])
PUBLIC_BASE_URL = str(DOMAIN_CONFIG["public_base_url"])
ACME_CONFIG = dict(RUNTIME_CONFIG.get("acme", {}))
ACME_CONFIG["domain"] = PORTAL_FQDN
ACME_CONFIG["cloudflare"] = dict(ACME_CONFIG.get("cloudflare", {}))
ACME_CONFIG["cloudflare"]["zone_name"] = str(DOMAIN_CONFIG["tld"])
ACME_STATE_DIR = Path(ACME_CONFIG.get("state_dir", "/var/lib/backup-portal/acme"))
LEGACY_CLOUDFLARE_CREDENTIALS_PATH = Path(
    str(ACME_CONFIG["cloudflare"].get("credentials_file", "/etc/backup-portal/cloudflare-acme.toml"))
)
USERNAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,23}$")
PORTAL_USER_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{2,31}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$")
PUBLIC_KEY_RE = re.compile(r"^ssh-ed25519 ([A-Za-z0-9+/]+={0,3})(?:\s+.*)?$")
POLICY_TARGET_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
LOGIN_FAILURES: dict[str, list[float]] = {}
SCHEDULER_STOP = threading.Event()
SCHEDULER_THREAD: threading.Thread | None = None
CHECKER_STOP = threading.Event()
CHECKER_WAKEUP = threading.Event()
CHECKER_THREAD: threading.Thread | None = None
AGENT_SCRIPT_LOCK = threading.Lock()
AGENT_SCRIPT_CACHE: tuple[tuple[int, int], str, bytes] | None = None
ARCHIVE_SCAN_LOCK = threading.BoundedSemaphore(2)
ARCHIVE_CACHE_LOCK = threading.Lock()
ARCHIVE_CACHE: OrderedDict[tuple[str, int, int], tuple[float, list[str], bool]] = OrderedDict()
LOG = logging.getLogger("backup-portal")

app = FastAPI(title="RAVEN", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=[PORTAL_FQDN])
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def now_ts() -> int:
    return int(time.time())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def token_cipher() -> Fernet:
    secret = str(CONFIG["security"].get("session_secret", ""))
    if len(secret) < 32:
        raise RuntimeError("[security].session_secret muss mindestens 32 Zeichen lang sein")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_deployment_token(value: str) -> str:
    return token_cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_deployment_token(value: str) -> str:
    try:
        return token_cipher().decrypt(value.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("Deployment-Token kann nicht entschluesselt werden") from exc


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Passwort muss mindestens 12 Zeichen lang sein")
    salt = secrets.token_bytes(16)
    # 16 MiB keeps hashing deliberately expensive while remaining compatible
    # with OpenSSL builds that enforce the common 32 MiB per-call ceiling.
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        kind, n, r, p, salt_b64, digest_b64 = encoded.split("$")
        if kind != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def legacy_cloudflare_credentials() -> dict[str, Any]:
    """Read the former root-only credential file once for SQLite migration."""
    path = LEGACY_CLOUDFLARE_CREDENTIALS_PATH
    try:
        file_stat = path.lstat()
        if (
            not statlib.S_ISREG(file_stat.st_mode)
            or path.is_symlink()
            or file_stat.st_uid != 0
            or statlib.S_IMODE(file_stat.st_mode) & 0o077
            or file_stat.st_size > 64 * 1024
        ):
            return {}
        if path.suffix.lower() == ".toml":
            with path.open("rb") as handle:
                values = tomllib.load(handle).get("cloudflare", {})
            return dict(values) if isinstance(values, dict) else {}
        values: dict[str, str] = {}
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line and not line.startswith(("#", ";")) and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        return {"api_token": values.get("dns_cloudflare_api_token", "")}
    except (FileNotFoundError, OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError):
        return {}


def migrate_policy_schedule(
    connection: sqlite3.Connection,
    policy_columns: set[str],
    client_columns: set[str],
    portal_defaults: dict[str, Any],
) -> None:
    """Move the backup schedule from the individual client onto its policy.

    Historically every client carried its own hour and minute and the interval
    was hard-wired to one calendar day. The schedule now lives on the policy so
    it can be changed centrally and picked up by every agent on its next poll.
    """
    if "schedule_hour" in policy_columns:
        return
    settings = connection.execute("SELECT * FROM portal_settings WHERE id=1").fetchone()
    default_hour = int(settings["default_schedule_hour"] if settings else portal_defaults["default_schedule_hour"])
    default_minute = int(settings["default_schedule_minute"] if settings else portal_defaults["default_schedule_minute"])
    connection.execute(
        f"ALTER TABLE backup_policies ADD COLUMN schedule_hour INTEGER NOT NULL DEFAULT {default_hour}"
    )
    connection.execute(
        f"ALTER TABLE backup_policies ADD COLUMN schedule_minute INTEGER NOT NULL DEFAULT {default_minute}"
    )
    connection.execute(
        "ALTER TABLE backup_policies ADD COLUMN interval_hours INTEGER NOT NULL DEFAULT "
        f"{backup_schedule.DEFAULT_INTERVAL_HOURS}"
    )
    if not {"schedule_hour", "schedule_minute"} <= client_columns:
        return
    # Clients of one policy shared a time in practice; adopt the most common one.
    for policy in connection.execute("SELECT id FROM backup_policies").fetchall():
        legacy = connection.execute(
            "SELECT schedule_hour,schedule_minute FROM clients WHERE policy_id=? "
            "GROUP BY schedule_hour,schedule_minute ORDER BY COUNT(*) DESC,schedule_hour,schedule_minute LIMIT 1",
            (policy["id"],),
        ).fetchone()
        if not legacy:
            continue
        connection.execute(
            "UPDATE backup_policies SET schedule_hour=?,schedule_minute=? WHERE id=?",
            (int(legacy["schedule_hour"]), int(legacy["schedule_minute"]), policy["id"]),
        )
    drop_legacy_client_columns(connection, "schedule_hour", "schedule_minute")


def drop_legacy_client_columns(connection: sqlite3.Connection, *columns: str) -> None:
    for column in columns:
        try:
            connection.execute(f"ALTER TABLE clients DROP COLUMN {column}")
        except sqlite3.OperationalError:
            LOG.warning("Historische Spalte clients.%s konnte nicht entfernt werden", column)


def migrate_policy_notifications(
    connection: sqlite3.Connection, policy_columns: set[str], client_columns: set[str]
) -> None:
    """Move the mail events from the individual client onto its policy.

    Which events deserve a mail is a property of how a group of servers is
    supervised, so it belongs next to the schedule on the policy.
    """
    if "mail_on_success" in policy_columns:
        return
    connection.execute("ALTER TABLE backup_policies ADD COLUMN mail_on_success INTEGER NOT NULL DEFAULT 1")
    connection.execute("ALTER TABLE backup_policies ADD COLUMN mail_on_failure INTEGER NOT NULL DEFAULT 1")
    connection.execute("ALTER TABLE backup_policies ADD COLUMN mail_on_skipped INTEGER NOT NULL DEFAULT 0")
    if not {"mail_on_success", "mail_on_failure"} <= client_columns:
        return
    for policy in connection.execute("SELECT id FROM backup_policies").fetchall():
        legacy = connection.execute(
            "SELECT mail_on_success,mail_on_failure FROM clients WHERE policy_id=? "
            "GROUP BY mail_on_success,mail_on_failure ORDER BY COUNT(*) DESC,mail_on_success DESC,mail_on_failure DESC "
            "LIMIT 1",
            (policy["id"],),
        ).fetchone()
        if not legacy:
            continue
        connection.execute(
            "UPDATE backup_policies SET mail_on_success=?,mail_on_failure=? WHERE id=?",
            (int(legacy["mail_on_success"]), int(legacy["mail_on_failure"]), policy["id"]),
        )
    drop_legacy_client_columns(connection, "mail_on_success", "mail_on_failure")


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with db() as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
              password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','viewer')),
              email TEXT NOT NULL DEFAULT '', receive_notifications INTEGER NOT NULL DEFAULT 0,
              active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              csrf_token TEXT NOT NULL, expires_at INTEGER NOT NULL, ip TEXT, user_agent TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS clients (
              id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL,
              source_hostname TEXT, home_path TEXT NOT NULL,
              run_initial_backup INTEGER NOT NULL DEFAULT 0,
              imported INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1,
              policy_id INTEGER REFERENCES backup_policies(id), agent_token_hash TEXT,
              agent_log_level TEXT NOT NULL DEFAULT 'INFO',
              agent_log_local INTEGER NOT NULL DEFAULT 1,
              agent_log_portal INTEGER NOT NULL DEFAULT 1,
              agent_log_traceback INTEGER NOT NULL DEFAULT 1,
              agent_log_max_bytes INTEGER NOT NULL DEFAULT 262144,
              agent_config_version INTEGER NOT NULL DEFAULT 1,
              agent_config_updated_at TEXT,
              mariadb_available INTEGER NOT NULL DEFAULT 0,
              agent_script_sha256 TEXT NOT NULL DEFAULT '',
              last_event TEXT, last_event_at TEXT, last_success_at TEXT,
              last_poll_at TEXT, last_payload TEXT,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS deployment_tokens (
              token_hash TEXT PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
              token_ciphertext TEXT, expires_at INTEGER NOT NULL, used_at TEXT,
              created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS status_events (
              id INTEGER PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
              event TEXT NOT NULL, run_id TEXT, payload TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS backup_policies (
              id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, description TEXT NOT NULL DEFAULT '',
              mariadb_enabled INTEGER NOT NULL DEFAULT 1,
              mariadb_databases_enabled INTEGER NOT NULL DEFAULT 1,
              mariadb_users_enabled INTEGER NOT NULL DEFAULT 1,
              schedule_hour INTEGER NOT NULL DEFAULT 2,
              schedule_minute INTEGER NOT NULL DEFAULT 0,
              interval_hours INTEGER NOT NULL DEFAULT 24,
              start_offset_minutes INTEGER NOT NULL DEFAULT 0,
              mail_on_success INTEGER NOT NULL DEFAULT 1,
              mail_on_failure INTEGER NOT NULL DEFAULT 1,
              mail_on_skipped INTEGER NOT NULL DEFAULT 0,
              active INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy_paths (
              id INTEGER PRIMARY KEY, policy_id INTEGER NOT NULL REFERENCES backup_policies(id) ON DELETE CASCADE,
              source_path TEXT NOT NULL, target_name TEXT NOT NULL,
              mode TEXT NOT NULL CHECK(mode IN ('sync','snapshot','tar')), sort_order INTEGER NOT NULL DEFAULT 0,
              UNIQUE(policy_id,source_path), UNIQUE(policy_id,target_name)
            );
            CREATE TABLE IF NOT EXISTS backup_commands (
              id INTEGER PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
              kind TEXT NOT NULL DEFAULT 'backup', reason TEXT NOT NULL, status TEXT NOT NULL,
              force INTEGER NOT NULL DEFAULT 0, due_at TEXT,
              schedule_key TEXT UNIQUE, requested_by INTEGER REFERENCES users(id), requested_at TEXT NOT NULL,
              policy_snapshot TEXT, claimed_at TEXT, started_at TEXT, finished_at TEXT, run_id TEXT, message TEXT
            );
            CREATE TABLE IF NOT EXISTS backup_run_logs (
              id INTEGER PRIMARY KEY,
              client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
              command_id INTEGER REFERENCES backup_commands(id) ON DELETE SET NULL,
              upload_id TEXT NOT NULL,
              run_id TEXT,
              status TEXT NOT NULL CHECK(status IN ('success','failure','test')),
              source_hostname TEXT NOT NULL,
              phase TEXT,
              started_at TEXT,
              finished_at TEXT NOT NULL,
              log_level TEXT NOT NULL,
              log_text TEXT NOT NULL,
              log_bytes INTEGER NOT NULL,
              truncated INTEGER NOT NULL DEFAULT 0,
              report_json TEXT NOT NULL DEFAULT '{}',
              received_at TEXT NOT NULL,
              UNIQUE(client_id,upload_id)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, target TEXT,
              details TEXT, ip TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS checker_settings (
              id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 1,
              interval_minutes INTEGER NOT NULL DEFAULT 60, next_run_at TEXT NOT NULL,
              mail_on_problem INTEGER NOT NULL DEFAULT 1,
              mail_on_recovery INTEGER NOT NULL DEFAULT 1,
              mail_on_clean_run INTEGER NOT NULL DEFAULT 0,
              alarm_on_unchanged INTEGER NOT NULL DEFAULT 0,
              reminder_hours INTEGER NOT NULL DEFAULT 24,
              updated_by INTEGER REFERENCES users(id), updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS smtp_settings (
              id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 1,
              host TEXT NOT NULL, port INTEGER NOT NULL,
              username TEXT NOT NULL DEFAULT '', password_ciphertext TEXT NOT NULL DEFAULT '',
              from_address TEXT NOT NULL, recipients_json TEXT NOT NULL,
              timeout_seconds INTEGER NOT NULL DEFAULT 20,
              updated_by INTEGER REFERENCES users(id), updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS acme_settings (
              id INTEGER PRIMARY KEY CHECK(id=1),
              cloudflare_token_ciphertext TEXT NOT NULL DEFAULT '',
              cloudflare_zone_id TEXT NOT NULL DEFAULT '',
              cloudflare_ttl INTEGER NOT NULL DEFAULT 60,
              updated_by INTEGER REFERENCES users(id), updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS portal_settings (
              id INTEGER PRIMARY KEY CHECK(id=1),
              domain_tld TEXT NOT NULL, domain_subdomain TEXT NOT NULL DEFAULT '',
              pending_domain_tld TEXT NOT NULL DEFAULT '',
              pending_domain_subdomain TEXT NOT NULL DEFAULT '',
              domain_change_pending INTEGER NOT NULL DEFAULT 0,
              username_prefix TEXT NOT NULL, backup_ssh_port INTEGER NOT NULL,
              remote_hostname TEXT NOT NULL, deployment_token_minutes INTEGER NOT NULL,
              default_schedule_hour INTEGER NOT NULL, default_schedule_minute INTEGER NOT NULL,
              default_interval_hours INTEGER NOT NULL DEFAULT 24,
              min_remote_free_bytes INTEGER NOT NULL,
              database_split_threshold_bytes INTEGER NOT NULL,
              updated_by INTEGER REFERENCES users(id), updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cloudflare_test_runs (
              id INTEGER PRIMARY KEY,
              status TEXT NOT NULL CHECK(status IN ('success','failure')),
              requested_by INTEGER REFERENCES users(id), tested_at TEXT NOT NULL,
              duration_ms INTEGER NOT NULL, message TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS checker_runs (
              id INTEGER PRIMARY KEY, mode TEXT NOT NULL CHECK(mode IN ('normal','force','dry_run','smtp_check','smtp_test')),
              status TEXT NOT NULL CHECK(status IN ('queued','running','success','problems','error','interrupted')),
              requested_by INTEGER REFERENCES users(id), requested_at TEXT NOT NULL,
              started_at TEXT, finished_at TEXT, exit_code INTEGER, summary TEXT, output TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_status_client_time ON status_events(client_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(id DESC);
            CREATE INDEX IF NOT EXISTS idx_commands_client_status ON backup_commands(client_id,status,id);
            CREATE INDEX IF NOT EXISTS idx_run_logs_client_time ON backup_run_logs(client_id,id DESC);
            CREATE INDEX IF NOT EXISTS idx_checker_runs_status ON checker_runs(status,id);
            CREATE INDEX IF NOT EXISTS idx_cloudflare_tests_time ON cloudflare_test_runs(id DESC);
            """
        )
        portal_defaults = bootstrap_settings(CONFIG)
        # Columns added by later releases must exist before the seed insert names them.
        portal_columns = {row[1] for row in connection.execute("PRAGMA table_info(portal_settings)")}
        if "default_interval_hours" not in portal_columns:
            connection.execute(
                "ALTER TABLE portal_settings ADD COLUMN default_interval_hours INTEGER NOT NULL DEFAULT "
                f"{backup_schedule.DEFAULT_INTERVAL_HOURS}"
            )
        connection.execute(
            "INSERT OR IGNORE INTO portal_settings("
            "id,domain_tld,domain_subdomain,username_prefix,backup_ssh_port,remote_hostname,"
            "deployment_token_minutes,default_schedule_hour,default_schedule_minute,default_interval_hours,"
            "min_remote_free_bytes,database_split_threshold_bytes,updated_at) "
            "VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                portal_defaults["domain_tld"], portal_defaults["domain_subdomain"],
                portal_defaults["username_prefix"], portal_defaults["backup_ssh_port"],
                portal_defaults["remote_hostname"], portal_defaults["deployment_token_minutes"],
                portal_defaults["default_schedule_hour"], portal_defaults["default_schedule_minute"],
                portal_defaults["default_interval_hours"], portal_defaults["min_remote_free_bytes"],
                portal_defaults["database_split_threshold_bytes"], now_iso(),
            ),
        )
        if "pending_domain_tld" not in portal_columns:
            connection.execute("ALTER TABLE portal_settings ADD COLUMN pending_domain_tld TEXT NOT NULL DEFAULT ''")
        if "pending_domain_subdomain" not in portal_columns:
            connection.execute("ALTER TABLE portal_settings ADD COLUMN pending_domain_subdomain TEXT NOT NULL DEFAULT ''")
        if "domain_change_pending" not in portal_columns:
            connection.execute("ALTER TABLE portal_settings ADD COLUMN domain_change_pending INTEGER NOT NULL DEFAULT 0")
        token_columns = {row[1] for row in connection.execute("PRAGMA table_info(deployment_tokens)")}
        if "token_ciphertext" not in token_columns:
            connection.execute("ALTER TABLE deployment_tokens ADD COLUMN token_ciphertext TEXT")
        client_columns = {row[1] for row in connection.execute("PRAGMA table_info(clients)")}
        if "last_poll_at" not in client_columns:
            connection.execute("ALTER TABLE clients ADD COLUMN last_poll_at TEXT")
        if "policy_id" not in client_columns:
            connection.execute("ALTER TABLE clients ADD COLUMN policy_id INTEGER REFERENCES backup_policies(id)")
        client_column_defaults = {
            "agent_log_level": "TEXT NOT NULL DEFAULT 'INFO'",
            "agent_log_local": "INTEGER NOT NULL DEFAULT 1",
            "agent_log_portal": "INTEGER NOT NULL DEFAULT 1",
            "agent_log_traceback": "INTEGER NOT NULL DEFAULT 1",
            "agent_log_max_bytes": "INTEGER NOT NULL DEFAULT 262144",
            "agent_config_version": "INTEGER NOT NULL DEFAULT 1",
            "agent_config_updated_at": "TEXT",
            "mariadb_available": "INTEGER NOT NULL DEFAULT 0",
            "agent_script_sha256": "TEXT NOT NULL DEFAULT ''",
            "last_success_at": "TEXT",
        }
        for column, definition in client_column_defaults.items():
            if column not in client_columns:
                connection.execute(f"ALTER TABLE clients ADD COLUMN {column} {definition}")
        if "last_success_at" not in client_columns:
            connection.execute(
                "UPDATE clients SET last_success_at="
                "(SELECT MAX(created_at) FROM status_events WHERE client_id=clients.id AND event='success')"
            )
        user_columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        if "email" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
        if "receive_notifications" not in user_columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN receive_notifications INTEGER NOT NULL DEFAULT 0"
            )
        command_columns = {row[1] for row in connection.execute("PRAGMA table_info(backup_commands)")}
        if "policy_snapshot" not in command_columns:
            connection.execute("ALTER TABLE backup_commands ADD COLUMN policy_snapshot TEXT")
        if "force" not in command_columns:
            connection.execute("ALTER TABLE backup_commands ADD COLUMN force INTEGER NOT NULL DEFAULT 0")
            connection.execute("UPDATE backup_commands SET force=1 WHERE reason='manual'")
        if "due_at" not in command_columns:
            connection.execute("ALTER TABLE backup_commands ADD COLUMN due_at TEXT")
        policy_columns = {row[1] for row in connection.execute("PRAGMA table_info(backup_policies)")}
        if "mariadb_databases_enabled" not in policy_columns:
            connection.execute("ALTER TABLE backup_policies ADD COLUMN mariadb_databases_enabled INTEGER NOT NULL DEFAULT 1")
            connection.execute("UPDATE backup_policies SET mariadb_databases_enabled=mariadb_enabled")
        if "mariadb_users_enabled" not in policy_columns:
            connection.execute("ALTER TABLE backup_policies ADD COLUMN mariadb_users_enabled INTEGER NOT NULL DEFAULT 1")
            connection.execute("UPDATE backup_policies SET mariadb_users_enabled=mariadb_enabled")
        migrate_policy_schedule(connection, policy_columns, client_columns, portal_defaults)
        migrate_policy_notifications(connection, policy_columns, client_columns)
        if "start_offset_minutes" not in policy_columns:
            connection.execute(
                "ALTER TABLE backup_policies ADD COLUMN start_offset_minutes INTEGER NOT NULL DEFAULT 0"
            )
        default_policy = connection.execute(
            "SELECT id,name FROM backup_policies WHERE name IN ('Standard Zstd Archive','Standard Snapshot') "
            "ORDER BY (name='Standard Zstd Archive') DESC LIMIT 1"
        ).fetchone()
        if not default_policy:
            cursor = connection.execute(
                "INSERT INTO backup_policies(name,description,mariadb_enabled,schedule_hour,schedule_minute,"
                "interval_hours,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    "Standard Zstd Archive",
                    "Standard-Policy: /etc und /home als persistente Tar.Zstd-Archive, MariaDB aktiviert.",
                    1,
                    portal_defaults["default_schedule_hour"],
                    portal_defaults["default_schedule_minute"],
                    portal_defaults["default_interval_hours"],
                    now_iso(),
                    now_iso(),
                ),
            )
            default_policy_id = cursor.lastrowid
            connection.executemany(
                "INSERT INTO policy_paths(policy_id,source_path,target_name,mode,sort_order) VALUES(?,?,?,?,?)",
                [
                    (default_policy_id, "/etc", "etc", "tar", 10),
                    (default_policy_id, "/home", "home", "tar", 20),
                ],
            )
        else:
            default_policy_id = default_policy["id"]
            if default_policy["name"] == "Standard Snapshot" and not connection.execute(
                "SELECT 1 FROM backup_policies WHERE name='Standard Zstd Archive'"
            ).fetchone():
                connection.execute(
                    "UPDATE backup_policies SET name='Standard Zstd Archive',description=?,updated_at=? WHERE id=?",
                    ("Standard-Policy: /etc und /home als persistente Tar.Zstd-Archive, MariaDB aktiviert.", now_iso(), default_policy_id),
                )
        connection.execute("UPDATE clients SET policy_id=? WHERE policy_id IS NULL", (default_policy_id,))
        migrated_policy_ids = [
            row[0] for row in connection.execute("SELECT DISTINCT policy_id FROM policy_paths WHERE mode='snapshot'")
        ]
        if migrated_policy_ids:
            migration_time = now_iso()
            connection.execute("UPDATE policy_paths SET mode='tar' WHERE mode='snapshot'")
            placeholders = ",".join("?" for _ in migrated_policy_ids)
            connection.execute(
                f"UPDATE backup_policies SET updated_at=? WHERE id IN ({placeholders})",
                (migration_time, *migrated_policy_ids),
            )
            connection.execute(
                f"UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? "
                f"WHERE policy_id IN ({placeholders})",
                (migration_time, *migrated_policy_ids),
            )
        queued_commands = connection.execute(
            "SELECT id,policy_snapshot FROM backup_commands WHERE status='queued' AND policy_snapshot IS NOT NULL"
        ).fetchall()
        for command in queued_commands:
            try:
                queued_policy = json.loads(command["policy_snapshot"])
                changed = False
                for item in queued_policy.get("paths", []):
                    if item.get("mode") == "snapshot":
                        item["mode"] = "tar"
                        changed = True
                if changed:
                    connection.execute(
                        "UPDATE backup_commands SET policy_snapshot=? WHERE id=?",
                        (json.dumps(queued_policy, ensure_ascii=False), command["id"]),
                    )
            except (TypeError, json.JSONDecodeError):
                LOG.warning("Policy-Snapshot von Auftrag %s konnte nicht auf tar.zst migriert werden", command["id"])
        checker_defaults = CONFIG.get("checker", {})
        checker_interval = max(5, min(1440, int(checker_defaults.get("interval_minutes", 60))))
        checker_enabled = bool(checker_defaults.get("enabled", True))
        checker_columns = {row[1] for row in connection.execute("PRAGMA table_info(checker_settings)")}
        checker_alert_defaults = {
            "mail_on_problem": "INTEGER NOT NULL DEFAULT 1",
            "mail_on_recovery": "INTEGER NOT NULL DEFAULT 1",
            "mail_on_clean_run": "INTEGER NOT NULL DEFAULT 0",
            "alarm_on_unchanged": "INTEGER NOT NULL DEFAULT 0",
            "reminder_hours": "INTEGER NOT NULL DEFAULT 24",
        }
        for column, definition in checker_alert_defaults.items():
            if column not in checker_columns:
                connection.execute(f"ALTER TABLE checker_settings ADD COLUMN {column} {definition}")
        connection.execute(
            "INSERT OR IGNORE INTO checker_settings(id,enabled,interval_minutes,next_run_at,updated_at) VALUES(1,?,?,?,?)",
            (
                checker_enabled,
                checker_interval,
                (datetime.now(timezone.utc) + timedelta(minutes=checker_interval)).isoformat(),
                now_iso(),
            ),
        )
        smtp_defaults = CONFIG.get("smtp", {})
        if smtp_defaults and not connection.execute("SELECT 1 FROM smtp_settings WHERE id=1").fetchone():
            password = str(smtp_defaults.get("password", ""))
            connection.execute(
                "INSERT INTO smtp_settings(id,enabled,host,port,username,password_ciphertext,from_address,"
                "recipients_json,timeout_seconds,updated_at) VALUES(1,?,?,?,?,?,?,?,?,?)",
                (
                    bool(smtp_defaults.get("enabled", True)),
                    str(smtp_defaults.get("host", "")),
                    int(smtp_defaults.get("port", 25)),
                    str(smtp_defaults.get("username", "")),
                    encrypt_deployment_token(password) if password else "",
                    str(smtp_defaults.get("from_address", "")),
                    json.dumps(list(smtp_defaults.get("to", []))),
                    int(smtp_defaults.get("timeout_seconds", 20)),
                    now_iso(),
                ),
            )
        smtp_row = connection.execute(
            "SELECT recipients_json FROM smtp_settings WHERE id=1"
        ).fetchone()
        if smtp_row and not connection.execute(
            "SELECT 1 FROM users WHERE receive_notifications=1"
        ).fetchone():
            try:
                legacy_recipients = [
                    str(item).strip()
                    for item in json.loads(smtp_row["recipients_json"] or "[]")
                    if str(item).strip() and EMAIL_RE.fullmatch(str(item).strip())
                ]
            except (TypeError, json.JSONDecodeError):
                legacy_recipients = []
            candidates = connection.execute(
                "SELECT id,email FROM users WHERE active=1 "
                "ORDER BY (role='admin') DESC,id"
            ).fetchall()
            for candidate, email in zip(candidates, legacy_recipients):
                connection.execute(
                    "UPDATE users SET email=?,receive_notifications=1 WHERE id=?",
                    (email, candidate["id"]),
                )
            if legacy_recipients and candidates:
                connection.execute(
                    "UPDATE smtp_settings SET recipients_json='[]' WHERE id=1"
                )
                connection.execute(
                    "UPDATE clients SET agent_config_version=agent_config_version+1,"
                    "agent_config_updated_at=? WHERE active=1",
                    (now_iso(),),
                )
        cloudflare_defaults = ACME_CONFIG.get("cloudflare", {})
        if not isinstance(cloudflare_defaults, dict):
            cloudflare_defaults = {}
        legacy_cloudflare = legacy_cloudflare_credentials()
        legacy_token = str(legacy_cloudflare.get("api_token", "")).strip()
        existing_acme = connection.execute("SELECT * FROM acme_settings WHERE id=1").fetchone()
        if not existing_acme:
            connection.execute(
                "INSERT INTO acme_settings(id,cloudflare_token_ciphertext,cloudflare_zone_id,cloudflare_ttl,updated_at) "
                "VALUES(1,?,?,?,?)",
                (
                    encrypt_deployment_token(legacy_token) if legacy_token else "",
                    str(legacy_cloudflare.get("zone_id", cloudflare_defaults.get("zone_id", ""))).strip(),
                    int(legacy_cloudflare.get("ttl", cloudflare_defaults.get("ttl", 60))),
                    now_iso(),
                ),
            )
        elif legacy_token:
            connection.execute(
                "UPDATE acme_settings SET cloudflare_token_ciphertext=?,updated_at=? WHERE id=1",
                (encrypt_deployment_token(legacy_token), now_iso()),
            )
    os.chmod(DB_PATH, 0o600)
    if (
        legacy_token
        and LEGACY_CLOUDFLARE_CREDENTIALS_PATH == Path("/etc/backup-portal/cloudflare-acme.toml")
        and not LEGACY_CLOUDFLARE_CREDENTIALS_PATH.is_symlink()
    ):
        try:
            LEGACY_CLOUDFLARE_CREDENTIALS_PATH.unlink()
            LOG.info("Legacy-Cloudflare-Credentials nach SQLite-Migration entfernt")
        except FileNotFoundError:
            pass


def acme_configuration(*, include_token: bool = False) -> dict[str, Any]:
    with db() as connection:
        row = connection.execute("SELECT * FROM acme_settings WHERE id=1").fetchone()
    if not row:
        return {"token_configured": False, "zone_id": "", "ttl": 60}
    token = decrypt_deployment_token(row["cloudflare_token_ciphertext"]) if row["cloudflare_token_ciphertext"] else ""
    result = {
        "token_configured": bool(token),
        "zone_id": row["cloudflare_zone_id"],
        "ttl": int(row["cloudflare_ttl"]),
        "updated_at": row["updated_at"],
    }
    if include_token:
        result["api_token"] = token
    return result


def application_settings(*, prefer_pending_domain: bool = False) -> dict[str, Any]:
    """Return database-owned settings and the public address derived from them."""
    values = effective_settings(CONFIG, prefer_pending_domain=prefer_pending_domain)
    derived_config = copy.deepcopy(CONFIG)
    derived_config["domain"] = {
        "tld": values["domain_tld"],
        "subdomain": values["domain_subdomain"],
    }
    resolved = resolve_domain_config(derived_config)
    values.update(
        {
            "fqdn": resolved["fqdn"],
            "public_base_url": resolved["public_base_url"],
            "portal_port": resolved["port"],
        }
    )
    return values


def normalized_email(value: str) -> str:
    email = value.strip()
    if email and (len(email) > 254 or not EMAIL_RE.fullmatch(email)):
        raise ValueError("Ungueltige E-Mail-Adresse")
    return email


def notification_recipients(connection: sqlite3.Connection | None = None) -> list[str]:
    owns_connection = connection is None
    active_connection = connection or db()
    try:
        rows = active_connection.execute(
            "SELECT email FROM users WHERE active=1 AND receive_notifications=1 "
            "AND TRIM(email)<>'' ORDER BY username"
        ).fetchall()
        recipients: list[str] = []
        seen: set[str] = set()
        for row in rows:
            try:
                email = normalized_email(str(row["email"]))
            except ValueError:
                continue
            identity = email.casefold()
            if identity not in seen:
                seen.add(identity)
                recipients.append(email)
        return recipients
    finally:
        if owns_connection:
            active_connection.close()


def smtp_configuration() -> dict[str, Any]:
    with db() as connection:
        row = connection.execute("SELECT * FROM smtp_settings WHERE id=1").fetchone()
        recipients = notification_recipients(connection)
    if not row:
        raise RuntimeError("SMTP ist noch nicht in SQLite konfiguriert")
    return {
        "enabled": bool(row["enabled"]) and bool(recipients),
        "configured_enabled": bool(row["enabled"]),
        "host": str(row["host"]),
        "port": int(row["port"]),
        "username": str(row["username"]),
        "password": decrypt_deployment_token(row["password_ciphertext"]) if row["password_ciphertext"] else "",
        "from_address": str(row["from_address"]),
        "to": recipients,
        "starttls": False,
        "timeout_seconds": int(row["timeout_seconds"]),
    }


def audit(request: Request | None, action: str, target: str = "", details: str = "", user_id: int | None = None) -> None:
    if request and user_id is None:
        session = session_user(request)
        user_id = session["id"] if session else None
    with db() as connection:
        connection.execute(
            "INSERT INTO audit_log(user_id,action,target,details,ip,created_at) VALUES(?,?,?,?,?,?)",
            (user_id, action, target, details[:2000], request.client.host if request and request.client else "", now_iso()),
        )


def import_existing_clients() -> int:
    imported = 0
    prefix = str(application_settings()["username_prefix"])
    with db() as connection:
        for home in sorted(HOME_ROOT.glob(prefix + "*")):
            if not home.is_dir():
                continue
            username = home.name
            try:
                account = pwd.getpwnam(username)
            except KeyError:
                continue
            slug = username[len(prefix):]
            source_hostname = None
            manifests = sorted(home.glob("[0-9]*/manifest.json"), reverse=True)
            for manifest in manifests:
                try:
                    source_hostname = json.loads(manifest.read_text(encoding="utf-8")).get("source_hostname")
                    if source_hostname:
                        break
                except Exception:
                    continue
            cursor = connection.execute(
                "INSERT OR IGNORE INTO clients(slug,username,source_hostname,home_path,imported,created_at) VALUES(?,?,?,?,1,?)",
                (slug, username, source_hostname, account.pw_dir, now_iso()),
            )
            imported += cursor.rowcount
    return imported


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


def render(request: Request, name: str, context: dict[str, Any], status_code: int = 200) -> HTMLResponse:
    user = session_user(request)
    merged = {"request": request, "user": user, "csrf": user["csrf_token"] if user else "", **context}
    return templates.TemplateResponse(name, merged, status_code=status_code)


def checker_results() -> dict[str, Any]:
    try:
        state = json.loads(CHECKER_STATE.read_text(encoding="utf-8"))
        return state.get("users", {})
    except Exception:
        return {}


def format_size(value: int | None) -> str:
    if value is None:
        return "–"
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(amount) < 1024 or unit == "PB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.2f} {unit}"
        amount /= 1024
    return str(value)


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


def parsed_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
    except (TypeError, ValueError):
        return None


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
        "schedule_hour": int(policy["schedule_hour"]),
        "schedule_minute": int(policy["schedule_minute"]),
        "interval_hours": int(policy["interval_hours"]),
        "start_offset_minutes": int(policy["start_offset_minutes"]),
        "mail_on_success": bool(policy["mail_on_success"]),
        "mail_on_failure": bool(policy["mail_on_failure"]),
        "mail_on_skipped": bool(policy["mail_on_skipped"]),
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
        if active:
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
        if not active:
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


def checker_loop() -> None:
    while not CHECKER_STOP.is_set():
        try:
            enqueue_due_checker()
            run = claim_checker_run()
            if run:
                execute_checker_run(run)
                continue
        except Exception:
            LOG.exception("Portal-Checker-Worker fehlgeschlagen")
        CHECKER_WAKEUP.wait(10)
        CHECKER_WAKEUP.clear()


def scheduler_loop() -> None:
    while not SCHEDULER_STOP.wait(30):
        try:
            enqueue_due_schedules()
        except Exception:
            LOG.exception("Zentraler Backup-Scheduler fehlgeschlagen")


@app.on_event("startup")
def startup() -> None:
    global SCHEDULER_THREAD, CHECKER_THREAD
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
    SCHEDULER_STOP.clear()
    SCHEDULER_THREAD = threading.Thread(target=scheduler_loop, name="backup-scheduler", daemon=True)
    SCHEDULER_THREAD.start()
    CHECKER_STOP.clear()
    CHECKER_WAKEUP.clear()
    CHECKER_THREAD = threading.Thread(target=checker_loop, name="checker-worker", daemon=True)
    CHECKER_THREAD.start()


@app.on_event("shutdown")
def shutdown() -> None:
    SCHEDULER_STOP.set()
    CHECKER_STOP.set()
    CHECKER_WAKEUP.set()
    if SCHEDULER_THREAD:
        SCHEDULER_THREAD.join(timeout=5)
    if CHECKER_THREAD:
        CHECKER_THREAD.join(timeout=5)


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
        "scheduler", "checker_script", "checker_config", "checker_worker",
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


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if session_user(request):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", {"error": ""})


@app.get("/manual", response_class=HTMLResponse)
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


@app.get("/settings/smtp", response_class=HTMLResponse)
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


@app.post("/settings/smtp")
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


@app.get("/settings/application", response_class=HTMLResponse)
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


@app.post("/settings/application")
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


def read_acme_state(name: str) -> dict[str, Any]:
    if name not in {"challenges.json", "job.json"}:
        return {}
    path = ACME_STATE_DIR / name
    try:
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return {}


def certificate_details() -> dict[str, Any]:
    managed_path = Path(f"/etc/letsencrypt/live/{application_settings()['fqdn']}/fullchain.pem")
    certificate_path = managed_path if managed_path.is_file() else Path(str(CONFIG["server"]["tls_cert"]))
    result: dict[str, Any] = {"path": str(certificate_path), "available": False}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
        try:
            sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        result.update(
            {
                "available": True,
                "subject": certificate.subject.rfc4514_string(),
                "issuer": certificate.issuer.rfc4514_string(),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_remaining": max(0, int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)),
                "expired": not_after <= datetime.now(timezone.utc),
                "sans": sans,
                "serial": format(certificate.serial_number, "X"),
                "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(":").upper(),
            }
        )
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def systemd_active(unit: str) -> bool:
    try:
        return subprocess.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", unit],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


MANAGED_SYSTEMD_UNITS = (
    "backup-portal.service",
    "backup-portal-cert-renew.timer",
    "backup-portal-cert-renew.service",
)


def systemd_unit_details(unit: str) -> dict[str, Any]:
    if unit not in MANAGED_SYSTEMD_UNITS:
        raise ValueError("Nicht verwaltete systemd Unit")
    details = {
        "name": unit,
        "kind": "systemd",
        "status": "unknown",
        "result": "Nicht verfügbar",
        "started_at": "",
        "finished_at": "",
        "details": "",
    }
    try:
        process = subprocess.run(
            [
                "/usr/bin/systemctl", "show", unit, "--no-pager",
                "--property=ActiveState,SubState,Result,ExecMainStatus,ActiveEnterTimestamp,InactiveEnterTimestamp",
            ],
            capture_output=True, text=True, timeout=10, check=False,
        )
        values = dict(
            line.split("=", 1) for line in process.stdout.splitlines() if "=" in line
        )
        active = values.get("ActiveState", "unknown")
        sub = values.get("SubState", "unknown")
        result = values.get("Result", "") or ("success" if active == "active" else active)
        details.update(
            {
                "status": "success" if active == "active" else "failure" if active == "failed" else "unknown",
                "result": result,
                "started_at": values.get("ActiveEnterTimestamp", ""),
                "finished_at": values.get("InactiveEnterTimestamp", ""),
                "details": f"{active}/{sub} · Exit {values.get('ExecMainStatus', '–')}",
            }
        )
        if process.returncode != 0:
            details["details"] = (process.stderr or details["details"])[:500]
    except (OSError, subprocess.TimeoutExpired) as exc:
        details["details"] = f"{type(exc).__name__}: {exc}"
    return details


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
                "started_at": "Portalstart", "finished_at": "", "details": "Checker-Warteschlange",
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
        cloudflare_tests = [dict(row) for row in connection.execute(
            "SELECT ct.*,u.username AS requested_by_name FROM cloudflare_test_runs ct "
            "LEFT JOIN users u ON u.id=ct.requested_by ORDER BY ct.id DESC LIMIT 20"
        ).fetchall()]
        clients = [dict(row) for row in connection.execute(
            "SELECT slug,last_poll_at,last_event,last_event_at FROM clients WHERE active=1 ORDER BY slug"
        ).fetchall()]
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
            "cloudflare_tests": cloudflare_tests,
            "acme_job": read_acme_state("job.json"),
            "online_agents": online,
            "agent_count": len(clients),
            "generated_at": now_iso(),
        },
    )


@app.get("/certificates", response_class=HTMLResponse)
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


@app.post("/certificates/cloudflare")
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


@app.post("/certificates/cloudflare/test")
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


@app.post("/certificates/request")
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


@app.post("/login", response_class=HTMLResponse)
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
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    expires = now_ts() + int(CONFIG["security"].get("session_hours", 12)) * 3600
    with db() as connection:
        connection.execute(
            "INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,ip,user_agent,created_at) VALUES(?,?,?,?,?,?,?)",
            (token_hash(raw), user["id"], csrf, expires, ip, request.headers.get("user-agent", "")[:500], now_iso()),
        )
    audit(request, "login.success", username, user_id=user["id"])
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("backup_portal_session", raw, secure=True, httponly=True, samesite="strict", max_age=expires-now_ts(), path="/")
    return response


@app.post("/logout")
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


ACTIVITY_LIMIT = 30
ACTIVITY_KINDS = ("all", "backup", "checker", "admin")
AUDIT_LABELS = {
    "backup.trigger": "Backup manuell angefordert",
    "backup.download": "Datei aus Backup geladen",
    "backup.archive_download": "Datei aus Archiv geladen",
    "certificate.request": "Zertifikat angefordert",
    "checker.settings": "Checker-Einstellungen geändert",
    "checker.trigger": "Checkerlauf gestartet",
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
        databases = (payload.get("mariadb") or {}).get("database_count")
        if isinstance(databases, int) and databases:
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


def system_account_exists(username: str) -> bool:
    try:
        pwd.getpwnam(str(username))
    except KeyError:
        return False
    return True


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


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request, sort: str = "server", direction: str = "asc", activity: str = "all"
):
    require_user(request)
    sort = sort if sort in {"server", "volume", "agent"} else "server"
    activity = activity if activity in ACTIVITY_KINDS else "all"
    direction = direction if direction in {"asc", "desc"} else "asc"
    checks = checker_results()
    with db() as connection:
        clients = [dict(row) for row in connection.execute("SELECT * FROM clients ORDER BY slug").fetchall()]
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
        counts[status if status in counts else "UNKNOWN"] += 1
    if sort == "volume":
        known = [client for client in clients if client["volume_bytes"] is not None]
        unknown = [client for client in clients if client["volume_bytes"] is None]
        known.sort(key=lambda client: client["slug"])
        known.sort(key=lambda client: client["volume_bytes"], reverse=direction == "desc")
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
            "message": request.query_params.get("message", ""),
        },
    )


@app.get("/checker", response_class=HTMLResponse)
def checker_page(request: Request):
    require_user(request)
    with db() as connection:
        settings = connection.execute("SELECT * FROM checker_settings WHERE id=1").fetchone()
        runs = connection.execute(
            "SELECT cr.*,u.username AS requested_by_name FROM checker_runs cr "
            "LEFT JOIN users u ON u.id=cr.requested_by ORDER BY cr.id DESC LIMIT 30"
        ).fetchall()
    state = checker_results()
    statuses = {"OK": 0, "STALE": 0, "ERROR": 0, "UNKNOWN": 0}
    for entry in state.values():
        status = str(entry.get("result", {}).get("status", "UNKNOWN")).upper()
        statuses[status if status in statuses else "UNKNOWN"] += 1
    return render(request, "checker.html", {
        "settings": dict(settings),
        "checker_mail_summary": checker_mail_summary(settings),
        "runs": runs,
        "statuses": statuses,
        "state_updated": datetime.fromtimestamp(CHECKER_STATE.stat().st_mtime).astimezone().isoformat(timespec="seconds")
        if CHECKER_STATE.is_file() else None,
        "script_path": str(CHECKER_SCRIPT),
        "config_path": str(CHECKER_CONFIG_PATH),
    })


@app.post("/checker/settings")
def checker_settings_update(
    request: Request,
    interval_minutes: int = Form(...),
    reminder_hours: int = Form(24),
    enabled: str | None = Form(None),
    mail_on_problem: str | None = Form(None),
    mail_on_recovery: str | None = Form(None),
    mail_on_clean_run: str | None = Form(None),
    alarm_on_unchanged: str | None = Form(None),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    if not 5 <= interval_minutes <= 1440:
        raise HTTPException(400, "Checker-Intervall muss zwischen 5 und 1440 Minuten liegen")
    if not 1 <= reminder_hours <= 720:
        raise HTTPException(400, "Erinnerungsabstand muss zwischen 1 und 720 Stunden liegen")
    with db() as connection:
        connection.execute(
            "UPDATE checker_settings SET enabled=?,interval_minutes=?,next_run_at=?,mail_on_problem=?,"
            "mail_on_recovery=?,mail_on_clean_run=?,alarm_on_unchanged=?,reminder_hours=?,"
            "updated_by=?,updated_at=? WHERE id=1",
            (
                bool(enabled), interval_minutes, checker_next_time(interval_minutes),
                bool(mail_on_problem), bool(mail_on_recovery), bool(mail_on_clean_run),
                bool(alarm_on_unchanged), reminder_hours, user["id"], now_iso(),
            ),
        )
    CHECKER_WAKEUP.set()
    audit(
        request, "checker.settings", "portal-checker",
        f"enabled={bool(enabled)}, interval={interval_minutes}, problem={bool(mail_on_problem)}, "
        f"recovery={bool(mail_on_recovery)}, clean={bool(mail_on_clean_run)}, "
        f"unchanged_alarm={bool(alarm_on_unchanged)}, reminder={reminder_hours}",
        user_id=user["id"],
    )
    return RedirectResponse("/checker", status_code=303)


@app.post("/checker/run")
def checker_run_trigger(
    request: Request,
    mode: str = Form(...),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    labels = {
        "normal": "normal",
        "force": "force-report",
        "dry_run": "dry-run",
        "smtp_check": "smtp-check",
        "smtp_test": "smtp-test",
    }
    if mode not in labels:
        raise HTTPException(400, "Ungueltiger Checker-Modus")
    run_id = enqueue_checker_run(mode, user["id"])
    if run_id is None:
        raise HTTPException(409, "Ein Checker-Lauf ist bereits queued oder aktiv")
    audit(request, "checker.trigger", "portal-checker", f"run_id={run_id}, mode={labels[mode]}", user_id=user["id"])
    return RedirectResponse("/checker", status_code=303)


@app.get("/checker/runs/{run_id}", response_class=HTMLResponse)
def checker_run_detail(request: Request, run_id: int):
    require_user(request, admin=True)
    with db() as connection:
        run = connection.execute(
            "SELECT cr.*,u.username AS requested_by_name FROM checker_runs cr "
            "LEFT JOIN users u ON u.id=cr.requested_by WHERE cr.id=?",
            (run_id,),
        ).fetchone()
    if not run:
        raise HTTPException(404, "Checker-Lauf nicht gefunden")
    return render(request, "checker_run.html", {"run": dict(run)})


ARCHIVE_SUFFIXES = (".tar.zst", ".tzst", ".tar.gz", ".tgz", ".tar")
EXPLORER_PAGE_SIZE = 200
EXPLORER_STAT_CHUNK = 256
EXPLORER_SORT_KEYS = ("name", "type", "size", "modified", "created")
EXPLORER_MAX_ARCHIVE_MEMBERS = 50_000
EXPLORER_ARCHIVE_CACHE_SECONDS = 300
EXPLORER_ARCHIVE_CACHE_ITEMS = 4


def explorer_client(client_id: int) -> sqlite3.Row:
    with db() as connection:
        client = connection.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    if not client:
        raise HTTPException(404, "Server nicht gefunden")
    return client


def client_home(client: sqlite3.Row) -> Path:
    try:
        root = HOME_ROOT.resolve(strict=True)
        home = Path(client["home_path"]).resolve(strict=True)
        home.relative_to(root)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        raise HTTPException(404, "Backup-Home ist nicht verfügbar") from exc
    if home.name != client["username"]:
        raise HTTPException(409, "Backup-Home stimmt nicht mit dem Zielkonto überein")
    return home


def safe_explorer_path(client: sqlite3.Row, raw_path: str, *, regular_file: bool = False) -> tuple[Path, str]:
    if "\x00" in raw_path or any(ord(char) < 32 for char in raw_path):
        raise HTTPException(400, "Ungültiger Pfad")
    relative = PurePosixPath(raw_path or ".")
    if relative.is_absolute() or ".." in relative.parts:
        raise HTTPException(400, "Ungültiger relativer Pfad")
    parts = [part for part in relative.parts if part not in {"", "."}]
    normalized = "/".join(parts)
    home = client_home(client)
    lexical = home.joinpath(*parts)
    try:
        if lexical.is_symlink():
            raise HTTPException(403, "Symbolische Links werden im Explorer nicht geöffnet")
        resolved = lexical.resolve(strict=True)
        resolved.relative_to(home)
    except FileNotFoundError as exc:
        raise HTTPException(404, "Backup-Pfad nicht gefunden") from exc
    except ValueError as exc:
        raise HTTPException(403, "Pfad liegt außerhalb des Backup-Homes") from exc
    if regular_file and not resolved.is_file():
        raise HTTPException(400, "Pfad ist keine reguläre Datei")
    return resolved, normalized


def is_archive(path: Path) -> bool:
    return path.name.lower().endswith(ARCHIVE_SUFFIXES)


def secure_open_regular(client: sqlite3.Row, relative: str) -> tuple[int, os.stat_result]:
    parts = [part for part in PurePosixPath(relative).parts if part not in {"", "."}]
    if not parts or ".." in parts:
        raise HTTPException(400, "Ungültiger Dateipfad")
    directory_fd = os.open(client_home(client), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
        info = os.fstat(file_fd)
        if not statlib.S_ISREG(info.st_mode):
            os.close(file_fd)
            raise HTTPException(400, "Pfad ist keine reguläre Datei")
        return file_fd, info
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise HTTPException(404, "Backup-Datei nicht gefunden") from exc
    except OSError as exc:
        raise HTTPException(403, "Backup-Datei kann nicht sicher geöffnet werden") from exc
    finally:
        os.close(directory_fd)


def secure_open_directory(client: sqlite3.Row, relative: str) -> int:
    parts = [part for part in PurePosixPath(relative or ".").parts if part not in {"", "."}]
    if ".." in parts:
        raise HTTPException(400, "Ungültiger Verzeichnispfad")
    directory_fd = os.open(client_home(client), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        for part in parts:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        result_fd = directory_fd
        directory_fd = -1
        return result_fd
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise HTTPException(404, "Backup-Verzeichnis nicht gefunden") from exc
    except OSError as exc:
        raise HTTPException(403, "Backup-Verzeichnis kann nicht sicher geöffnet werden") from exc
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)


def archive_list_command(path: Path, source: str | None = None) -> list[str]:
    lowered = path.name.lower()
    source = source or str(path)
    if lowered.endswith((".tar.zst", ".tzst")):
        return ["/usr/bin/tar", "--zstd", "-tf", source]
    if lowered.endswith((".tar.gz", ".tgz")):
        return ["/usr/bin/tar", "-tzf", source]
    return ["/usr/bin/tar", "-tf", source]


def archive_extract_command(path: Path, member: str, source: str | None = None) -> list[str]:
    lowered = path.name.lower()
    source = source or str(path)
    if lowered.endswith((".tar.zst", ".tzst")):
        return ["/usr/bin/tar", "--zstd", "-xOf", source, "--", member]
    if lowered.endswith((".tar.gz", ".tgz")):
        return ["/usr/bin/tar", "-xzOf", source, "--", member]
    return ["/usr/bin/tar", "-xOf", source, "--", member]


def normalized_archive_member(value: str) -> str | None:
    value = value.rstrip("\r\n")
    is_directory = value.endswith("/")
    while value.startswith("./"):
        value = value[2:]
    if not value or "\x00" in value or any(ord(char) < 32 for char in value):
        return None
    member = PurePosixPath(value)
    if member.is_absolute() or ".." in member.parts:
        return None
    normalized = member.as_posix()
    return normalized + "/" if is_directory and normalized != "." else normalized


def archive_members(
    path: Path, archive_fd: int | None = None, archive_info: os.stat_result | None = None
) -> tuple[list[str], bool]:
    info = archive_info or path.stat()
    cache_key = (str(path), info.st_size, info.st_mtime_ns)
    now = time.monotonic()
    with ARCHIVE_CACHE_LOCK:
        cached = ARCHIVE_CACHE.get(cache_key)
        if cached and now - cached[0] <= EXPLORER_ARCHIVE_CACHE_SECONDS:
            ARCHIVE_CACHE.move_to_end(cache_key)
            return cached[1], cached[2]
        for key, value in list(ARCHIVE_CACHE.items()):
            if now - value[0] > EXPLORER_ARCHIVE_CACHE_SECONDS or key[0] == str(path):
                ARCHIVE_CACHE.pop(key, None)
    if not ARCHIVE_SCAN_LOCK.acquire(blocking=False):
        raise HTTPException(429, "Zu viele gleichzeitige Archivabfragen")
    process: subprocess.Popen[str] | None = None
    timed_out = threading.Event()
    timer: threading.Timer | None = None
    try:
        archive_source = f"/proc/self/fd/{archive_fd}" if archive_fd is not None else str(path)
        process = subprocess.Popen(
            archive_list_command(path, archive_source),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            bufsize=1,
            pass_fds=(archive_fd,) if archive_fd is not None else (),
        )
        timer = threading.Timer(90, lambda: (timed_out.set(), process.kill()))
        timer.start()
        members: list[str] = []
        truncated = False
        assert process.stdout is not None
        for line in process.stdout:
            member = normalized_archive_member(line)
            if member is not None:
                members.append(member)
            if len(members) >= EXPLORER_MAX_ARCHIVE_MEMBERS:
                truncated = True
                process.terminate()
                break
        stderr = process.stderr.read() if process.stderr else ""
        return_code = process.wait()
        if timed_out.is_set():
            raise HTTPException(504, "Archiv-Inhaltsverzeichnis hat das Zeitlimit überschritten")
        if return_code != 0 and not truncated:
            LOG.warning("Archivliste fehlgeschlagen: %s: %s", path, stderr[-1000:])
            raise HTTPException(422, "Archiv konnte nicht gelesen werden")
        with ARCHIVE_CACHE_LOCK:
            ARCHIVE_CACHE[cache_key] = (time.monotonic(), members, truncated)
            ARCHIVE_CACHE.move_to_end(cache_key)
            while len(ARCHIVE_CACHE) > EXPLORER_ARCHIVE_CACHE_ITEMS:
                ARCHIVE_CACHE.popitem(last=False)
        return members, truncated
    finally:
        if timer:
            timer.cancel()
        if process and process.poll() is None:
            process.kill()
            process.wait()
        ARCHIVE_SCAN_LOCK.release()


def validated_archive_prefix(raw_prefix: str) -> str:
    if "\x00" in raw_prefix or any(ord(char) < 32 for char in raw_prefix):
        raise HTTPException(400, "Ungültiger Archivpfad")
    prefix = PurePosixPath(raw_prefix or ".")
    if prefix.is_absolute() or ".." in prefix.parts:
        raise HTTPException(400, "Ungültiger Archivpfad")
    return "/".join(part for part in prefix.parts if part not in {"", "."}).rstrip("/")


def explorer_breadcrumbs(client: sqlite3.Row, relative: str) -> list[dict[str, str]]:
    crumbs = [{"name": client["slug"], "path": ""}]
    current: list[str] = []
    for part in PurePosixPath(relative or ".").parts:
        if part in {"", "."}:
            continue
        current.append(part)
        crumbs.append({"name": part, "path": "/".join(current)})
    return crumbs


@app.get("/explorer", response_class=HTMLResponse)
def explorer_index(request: Request):
    require_user(request, admin=True)
    with db() as connection:
        clients = connection.execute("SELECT * FROM clients ORDER BY slug").fetchall()
    return render(request, "explorer_index.html", {"clients": clients})


def birth_times(directory_fd: int, names: list[str]) -> dict[str, int]:
    """Read statx birth times, which os.stat does not expose on Linux.

    The paths are anchored at the already validated directory descriptor so the
    lookup cannot leave the backup home, and stat never follows a symlink.
    """
    result: dict[str, int] = {}
    for offset in range(0, len(names), EXPLORER_STAT_CHUNK):
        chunk = names[offset:offset + EXPLORER_STAT_CHUNK]
        arguments = [f"/proc/self/fd/{directory_fd}/{name}" for name in chunk]
        try:
            process = subprocess.run(
                ["/usr/bin/stat", "--printf", "%W\\n", "--", *arguments],
                capture_output=True,
                text=True,
                timeout=30,
                pass_fds=(directory_fd,),
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return result
        for name, line in zip(chunk, process.stdout.splitlines()):
            try:
                created = int(line.strip())
            except ValueError:
                continue
            if created > 0:
                result[name] = created
    return result


def explorer_sort_key(sort: str) -> Any:
    """Return the sort key for a listing; the default groups directories first."""
    if sort == "size":
        return lambda item: (item[1].st_size, item[0].casefold())
    if sort == "modified":
        return lambda item: (item[1].st_mtime, item[0].casefold())
    if sort == "created":
        return lambda item: (item[2] or item[1].st_mtime, item[0].casefold())
    if sort == "type":
        return lambda item: (not statlib.S_ISDIR(item[1].st_mode), Path(item[0]).suffix.casefold(), item[0].casefold())
    return lambda item: (not statlib.S_ISDIR(item[1].st_mode), item[0].casefold())


@app.get("/clients/{client_id}/explorer", response_class=HTMLResponse)
def explorer_directory(
    request: Request,
    client_id: int,
    path: str = "",
    page: int = 1,
    sort: str = "name",
    direction: str = "asc",
):
    require_user(request, admin=True)
    client = explorer_client(client_id)
    directory, relative = safe_explorer_path(client, path)
    if not directory.is_dir():
        raise HTTPException(400, "Pfad ist kein Verzeichnis")
    page = max(1, page)
    sort = sort if sort in EXPLORER_SORT_KEYS else "name"
    direction = direction if direction in {"asc", "desc"} else "asc"
    entries: list[dict[str, Any]] = []
    directory_fd = secure_open_directory(client, relative)
    try:
        listing: list[tuple[str, os.stat_result]] = []
        for name in os.listdir(directory_fd):
            if not relative and name.startswith("."):
                continue
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                continue
            listing.append((name, info))
        created_times = birth_times(directory_fd, [name for name, _info in listing])
    except OSError as exc:
        raise HTTPException(403, "Verzeichnis kann nicht gelesen werden") from exc
    finally:
        os.close(directory_fd)
    children = [(name, info, created_times.get(name, 0)) for name, info in listing]
    children.sort(key=explorer_sort_key(sort), reverse=direction == "desc")
    total = len(children)
    start = (page - 1) * EXPLORER_PAGE_SIZE
    for name, info, created in children[start:start + EXPLORER_PAGE_SIZE]:
        is_link = statlib.S_ISLNK(info.st_mode)
        is_dir = statlib.S_ISDIR(info.st_mode)
        is_file = statlib.S_ISREG(info.st_mode)
        entry_relative = "/".join(filter(None, (relative, name)))
        entries.append({
            "name": name,
            "path": entry_relative,
            "is_dir": is_dir,
            "is_file": is_file,
            "is_link": is_link,
            "is_archive": is_file and is_archive(Path(name)),
            "size": format_size(info.st_size) if is_file else "–",
            "modified": datetime.fromtimestamp(info.st_mtime).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
            "created": datetime.fromtimestamp(created).astimezone().strftime("%Y-%m-%d %H:%M:%S") if created else "–",
        })
    return render(request, "explorer_directory.html", {
        "client": dict(client),
        "relative": relative,
        "breadcrumbs": explorer_breadcrumbs(client, relative),
        "entries": entries,
        "page": page,
        "pages": max(1, (total + EXPLORER_PAGE_SIZE - 1) // EXPLORER_PAGE_SIZE),
        "total": total,
        "sort": sort,
        "direction": direction,
    })


@app.get("/clients/{client_id}/explorer/download")
def explorer_download(request: Request, client_id: int, path: str):
    user = require_user(request, admin=True)
    client = explorer_client(client_id)
    file_path, relative = safe_explorer_path(client, path, regular_file=True)
    file_fd, info = secure_open_regular(client, relative)
    try:
        audit(request, "backup.download", client["slug"], relative, user_id=user["id"])
        media_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        disposition = f"attachment; filename*=UTF-8''{quote(file_path.name, safe='')}"
        return StreamingResponse(
            stream_open_file(file_fd),
            media_type=media_type,
            headers={"Content-Disposition": disposition, "Content-Length": str(info.st_size)},
            background=BackgroundTask(close_fd, file_fd),
        )
    except Exception:
        os.close(file_fd)
        raise


@app.get("/clients/{client_id}/explorer/archive", response_class=HTMLResponse)
def explorer_archive(request: Request, client_id: int, path: str, prefix: str = "", page: int = 1):
    require_user(request, admin=True)
    client = explorer_client(client_id)
    archive_path, relative = safe_explorer_path(client, path, regular_file=True)
    if not is_archive(archive_path):
        raise HTTPException(400, "Datei ist kein unterstütztes Tar-Archiv")
    prefix = validated_archive_prefix(prefix)
    archive_parent_path = PurePosixPath(relative).parent
    archive_parent = "" if archive_parent_path == PurePosixPath(".") else archive_parent_path.as_posix()
    archive_fd, archive_info = secure_open_regular(client, relative)
    try:
        members, truncated = archive_members(archive_path, archive_fd, archive_info)
    finally:
        os.close(archive_fd)
    base = prefix + "/" if prefix else ""
    children: dict[str, dict[str, Any]] = {}
    for member in members:
        if not member.startswith(base):
            continue
        remainder = member[len(base):]
        if not remainder:
            continue
        name, separator, _tail = remainder.partition("/")
        if not name:
            continue
        is_dir = bool(separator) or member.endswith("/")
        existing = children.get(name)
        if existing and existing["is_dir"]:
            continue
        children[name] = {
            "name": name,
            "is_dir": is_dir,
            "prefix": "/".join(filter(None, (prefix, name))),
            "member": member.rstrip("/"),
        }
    archive_crumbs = [{"name": archive_path.name, "prefix": ""}]
    current: list[str] = []
    for part in PurePosixPath(prefix or ".").parts:
        if part in {"", "."}:
            continue
        current.append(part)
        archive_crumbs.append({"name": part, "prefix": "/".join(current)})
    page = max(1, page)
    sorted_children = sorted(children.values(), key=lambda item: (not item["is_dir"], item["name"].casefold()))
    total = len(sorted_children)
    start = (page - 1) * EXPLORER_PAGE_SIZE
    return render(request, "explorer_archive.html", {
        "client": dict(client),
        "archive_path": relative,
        "archive_name": archive_path.name,
        "prefix": prefix,
        "archive_parent": archive_parent,
        "breadcrumbs": explorer_breadcrumbs(client, archive_parent),
        "archive_breadcrumbs": archive_crumbs,
        "entries": sorted_children[start:start + EXPLORER_PAGE_SIZE],
        "page": page,
        "pages": max(1, (total + EXPLORER_PAGE_SIZE - 1) // EXPLORER_PAGE_SIZE),
        "total": total,
        "truncated": truncated,
        "member_count": len(members),
    })


def archive_member_is_downloadable(
    path: Path, requested: str, archive_fd: int, archive_info: os.stat_result
) -> bool:
    member = normalized_archive_member(requested)
    if member is None or member.endswith("/"):
        return False
    members, truncated = archive_members(path, archive_fd, archive_info)
    if truncated and member not in members:
        raise HTTPException(413, "Archiv ist zu groß für eine sichere Einzeldownload-Prüfung")
    return member in members


def stream_archive_member(path: Path, member: str, archive_fd: int):
    source = f"/proc/self/fd/{archive_fd}"
    process = subprocess.Popen(
        archive_extract_command(path, member, source),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        pass_fds=(archive_fd,),
    )
    try:
        assert process.stdout is not None
        while chunk := process.stdout.read(1024 * 1024):
            yield chunk
        return_code = process.wait()
        if return_code != 0:
            LOG.warning("Archivdatei konnte nicht vollständig gestreamt werden: %s:%s", path, member)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def stream_open_file(file_fd: int):
    while chunk := os.read(file_fd, 1024 * 1024):
        yield chunk


def close_fd(file_fd: int) -> None:
    try:
        os.close(file_fd)
    except OSError:
        pass


@app.get("/clients/{client_id}/explorer/archive/download")
def explorer_archive_download(request: Request, client_id: int, path: str, member: str):
    user = require_user(request, admin=True)
    client = explorer_client(client_id)
    archive_path, relative = safe_explorer_path(client, path, regular_file=True)
    if not is_archive(archive_path):
        raise HTTPException(400, "Datei ist kein unterstütztes Tar-Archiv")
    archive_fd, archive_info = secure_open_regular(client, relative)
    normalized_member = normalized_archive_member(member)
    try:
        if normalized_member is None or not archive_member_is_downloadable(
            archive_path, normalized_member, archive_fd, archive_info
        ):
            raise HTTPException(404, "Datei ist nicht im Archiv vorhanden")
    except Exception:
        os.close(archive_fd)
        raise
    try:
        audit(request, "backup.archive_download", client["slug"], f"{relative}:{normalized_member}", user_id=user["id"])
        filename = PurePosixPath(normalized_member).name or "backup-file"
        media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        disposition = f"attachment; filename*=UTF-8''{quote(filename, safe='')}"
        return StreamingResponse(
            stream_archive_member(archive_path, normalized_member, archive_fd),
            media_type=media_type,
            headers={"Content-Disposition": disposition},
            background=BackgroundTask(close_fd, archive_fd),
        )
    except Exception:
        os.close(archive_fd)
        raise


def active_policies() -> list[sqlite3.Row]:
    with db() as connection:
        return connection.execute(
            "SELECT * FROM backup_policies WHERE active=1 ORDER BY name"
        ).fetchall()


def checker_mail_summary(settings: sqlite3.Row) -> str:
    """Name the check results the checker sends mail for."""
    events = [
        label
        for column, label in (
            ("mail_on_problem", "Probleme"),
            ("mail_on_recovery", "Wiederherstellung"),
            ("mail_on_clean_run", "fehlerfreier Lauf"),
        )
        if settings[column]
    ]
    if not events:
        return "keine"
    return f"{', '.join(events)} · Erinnerung alle {int(settings['reminder_hours'])} h"


def policy_mail_summary(policy: sqlite3.Row) -> str:
    """Name the backup events a policy sends mail for."""
    events = [
        label
        for column, label in (
            ("mail_on_success", "Erfolg"),
            ("mail_on_failure", "Fehler"),
            ("mail_on_skipped", "Ablehnung"),
        )
        if policy[column]
    ]
    return ", ".join(events) if events else "keine"


def validated_schedule(
    hour: Any, minute: Any, interval_hours: Any, offset_minutes: Any = 0
) -> tuple[int, int, int, int]:
    try:
        hours = backup_schedule.normalized_interval_hours(interval_hours)
        return (
            backup_schedule.normalized_hour(hour),
            backup_schedule.normalized_minute(minute),
            hours,
            backup_schedule.normalized_offset_minutes(offset_minutes, hours),
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, str(exc) or "Ungueltiger Zeitplan") from exc


def validated_policy_path(source_path: str, target_name: str, mode: str) -> tuple[str, str, str]:
    source_path = source_path.strip().rstrip("/") or "/"
    target_name = target_name.strip().lower()
    path = Path(source_path)
    if not path.is_absolute() or source_path == "/" or ".." in path.parts or any(ord(char) < 32 for char in source_path):
        raise HTTPException(400, "Quellpfad muss ein sicherer absoluter Ordnerpfad unterhalb von / sein")
    if not POLICY_TARGET_RE.fullmatch(target_name):
        raise HTTPException(400, "Zielname muss mit Kleinbuchstaben beginnen und darf nur a-z, 0-9, _ und - enthalten")
    if mode not in {"sync", "tar"}:
        raise HTTPException(400, "Ungueltiger Policy-Modus")
    return source_path, target_name, mode


@app.get("/policies", response_class=HTMLResponse)
def policies_page(request: Request):
    require_user(request)
    with db() as connection:
        policies = connection.execute(
            "SELECT p.*,COUNT(DISTINCT c.id) AS client_count,COUNT(DISTINCT pp.id) AS path_count "
            "FROM backup_policies p LEFT JOIN clients c ON c.policy_id=p.id "
            "LEFT JOIN policy_paths pp ON pp.policy_id=p.id GROUP BY p.id ORDER BY p.name"
        ).fetchall()
    defaults = application_settings()
    return render(
        request,
        "policies.html",
        {
            "policies": policies,
            "schedules": {
                policy["id"]: backup_schedule.describe(
                    policy["schedule_hour"], policy["schedule_minute"], policy["interval_hours"],
                    policy["start_offset_minutes"]
                )
                for policy in policies
            },
            "mail_summaries": {policy["id"]: policy_mail_summary(policy) for policy in policies},
            "interval_choices": backup_schedule.INTERVAL_CHOICES,
            "defaults": defaults,
            "message": request.query_params.get("message", ""),
        },
    )


@app.post("/policies")
def policy_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    schedule_hour: int = Form(...),
    schedule_minute: int = Form(...),
    interval_hours: int = Form(...),
    start_offset_minutes: int = Form(0),
    mariadb_databases_enabled: str | None = Form(None),
    mariadb_users_enabled: str | None = Form(None),
    mail_on_success: str | None = Form(None),
    mail_on_failure: str | None = Form(None),
    mail_on_skipped: str | None = Form(None),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    name = name.strip()
    if not (3 <= len(name) <= 80):
        raise HTTPException(400, "Policy-Name muss 3 bis 80 Zeichen lang sein")
    schedule_hour, schedule_minute, interval_hours, start_offset_minutes = validated_schedule(
        schedule_hour, schedule_minute, interval_hours, start_offset_minutes
    )
    try:
        with db() as connection:
            databases_enabled = bool(mariadb_databases_enabled)
            users_enabled = bool(mariadb_users_enabled)
            cursor = connection.execute(
                "INSERT INTO backup_policies(name,description,mariadb_enabled,mariadb_databases_enabled,"
                "mariadb_users_enabled,schedule_hour,schedule_minute,interval_hours,start_offset_minutes,"
                "mail_on_success,mail_on_failure,mail_on_skipped,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (name, description.strip()[:1000], databases_enabled or users_enabled,
                 databases_enabled, users_enabled, schedule_hour, schedule_minute, interval_hours,
                 start_offset_minutes, bool(mail_on_success), bool(mail_on_failure),
                 bool(mail_on_skipped), now_iso(), now_iso()),
            )
            policy_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Policy-Name existiert bereits")
    audit(request, "policy.create", name, f"policy_id={policy_id}", user_id=user["id"])
    return RedirectResponse(f"/policies/{policy_id}", status_code=303)


@app.get("/policies/{policy_id}", response_class=HTMLResponse)
def policy_detail(request: Request, policy_id: int):
    require_user(request)
    with db() as connection:
        policy = connection.execute("SELECT * FROM backup_policies WHERE id=?", (policy_id,)).fetchone()
        paths = connection.execute(
            "SELECT * FROM policy_paths WHERE policy_id=? ORDER BY sort_order,id", (policy_id,)
        ).fetchall()
        clients = connection.execute(
            "SELECT id,slug,source_hostname FROM clients WHERE policy_id=? ORDER BY slug", (policy_id,)
        ).fetchall()
        if not policy:
            raise HTTPException(404)
        copy_name = suggested_copy_name(connection, str(policy["name"]))
    now = datetime.now().astimezone()
    _current, following = backup_schedule.schedule_window(
        now, policy["schedule_hour"], policy["schedule_minute"], policy["interval_hours"]
    )
    return render(
        request,
        "policy_detail.html",
        {
            "policy": policy,
            "paths": paths,
            "clients": clients,
            "interval_choices": backup_schedule.INTERVAL_CHOICES,
            "schedule_description": backup_schedule.describe(
                policy["schedule_hour"], policy["schedule_minute"], policy["interval_hours"],
                policy["start_offset_minutes"]
            ),
            "next_slot": following,
            "copy_name": copy_name,
            "message": request.query_params.get("message", ""),
        },
    )


@app.post("/policies/{policy_id}")
def policy_update(
    request: Request,
    policy_id: int,
    name: str = Form(...),
    description: str = Form(""),
    schedule_hour: int = Form(...),
    schedule_minute: int = Form(...),
    interval_hours: int = Form(...),
    start_offset_minutes: int = Form(0),
    mariadb_databases_enabled: str | None = Form(None),
    mariadb_users_enabled: str | None = Form(None),
    mail_on_success: str | None = Form(None),
    mail_on_failure: str | None = Form(None),
    mail_on_skipped: str | None = Form(None),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    name = name.strip()
    if not (3 <= len(name) <= 80):
        raise HTTPException(400, "Policy-Name muss 3 bis 80 Zeichen lang sein")
    schedule_hour, schedule_minute, interval_hours, start_offset_minutes = validated_schedule(
        schedule_hour, schedule_minute, interval_hours, start_offset_minutes
    )
    try:
        with db() as connection:
            if not connection.execute("SELECT 1 FROM backup_policies WHERE id=?", (policy_id,)).fetchone():
                raise HTTPException(404)
            databases_enabled = bool(mariadb_databases_enabled)
            users_enabled = bool(mariadb_users_enabled)
            connection.execute(
                "UPDATE backup_policies SET name=?,description=?,mariadb_enabled=?,"
                "mariadb_databases_enabled=?,mariadb_users_enabled=?,schedule_hour=?,schedule_minute=?,"
                "interval_hours=?,start_offset_minutes=?,mail_on_success=?,mail_on_failure=?,"
                "mail_on_skipped=?,updated_at=? WHERE id=?",
                (name, description.strip()[:1000], databases_enabled or users_enabled,
                 databases_enabled, users_enabled, schedule_hour, schedule_minute, interval_hours,
                 start_offset_minutes, bool(mail_on_success), bool(mail_on_failure),
                 bool(mail_on_skipped), now_iso(), policy_id),
            )
            connection.execute(
                "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE policy_id=?",
                (now_iso(), policy_id),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Policy-Name existiert bereits")
    audit(request, "policy.update", name, f"policy_id={policy_id}", user_id=user["id"])
    return RedirectResponse(f"/policies/{policy_id}", status_code=303)


POLICY_NAME_MAX = 80


def policy_name_with_suffix(name: str, suffix: str) -> str:
    """Append a suffix and keep the result inside the allowed name length."""
    return f"{name[:POLICY_NAME_MAX - len(suffix)].rstrip()}{suffix}"


def suggested_copy_name(connection: sqlite3.Connection, name: str) -> str:
    """Return an unused name for a copy of the given policy."""
    candidate = policy_name_with_suffix(name, " (Kopie)")
    counter = 2
    while connection.execute("SELECT 1 FROM backup_policies WHERE name=?", (candidate,)).fetchone():
        candidate = policy_name_with_suffix(name, f" (Kopie {counter})")
        counter += 1
        if counter > 99:
            raise HTTPException(409, "Es existieren bereits zu viele Kopien dieser Policy")
    return candidate


@app.post("/policies/{policy_id}/duplicate")
def policy_duplicate(
    request: Request, policy_id: int, name: str = Form(""), csrf_token: str = Form(...)
):
    """Copy a policy including its path rules, but without its server assignments."""
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    try:
        with db() as connection:
            source = connection.execute(
                "SELECT * FROM backup_policies WHERE id=?", (policy_id,)
            ).fetchone()
            if not source:
                raise HTTPException(404)
            new_name = name.strip() or suggested_copy_name(connection, str(source["name"]))
            if not (3 <= len(new_name) <= POLICY_NAME_MAX):
                raise HTTPException(400, f"Policy-Name muss 3 bis {POLICY_NAME_MAX} Zeichen lang sein")
            cursor = connection.execute(
                "INSERT INTO backup_policies(name,description,mariadb_enabled,mariadb_databases_enabled,"
                "mariadb_users_enabled,schedule_hour,schedule_minute,interval_hours,start_offset_minutes,"
                "mail_on_success,mail_on_failure,mail_on_skipped,active,created_at,updated_at) "
                "SELECT ?,description,mariadb_enabled,mariadb_databases_enabled,mariadb_users_enabled,"
                "schedule_hour,schedule_minute,interval_hours,start_offset_minutes,mail_on_success,"
                "mail_on_failure,mail_on_skipped,active,?,? FROM backup_policies WHERE id=?",
                (new_name, now_iso(), now_iso(), policy_id),
            )
            new_id = int(cursor.lastrowid)
            connection.execute(
                "INSERT INTO policy_paths(policy_id,source_path,target_name,mode,sort_order) "
                "SELECT ?,source_path,target_name,mode,sort_order FROM policy_paths WHERE policy_id=?",
                (new_id, policy_id),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "Policy-Name existiert bereits") from exc
    audit(request, "policy.duplicate", new_name, f"source_policy_id={policy_id}", user_id=user["id"])
    message = f"Kopie von „{source['name']}“ angelegt; noch keinem Server zugewiesen"
    return RedirectResponse(f"/policies/{new_id}?message={quote(message)}", status_code=303)


@app.post("/policies/{policy_id}/delete")
def policy_delete(request: Request, policy_id: int, csrf_token: str = Form(...)):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    try:
        with db() as connection:
            # Lock writers before checking the assignment so a concurrent client
            # update cannot attach the policy between the check and the delete.
            connection.execute("BEGIN IMMEDIATE")
            policy = connection.execute(
                "SELECT name FROM backup_policies WHERE id=?", (policy_id,)
            ).fetchone()
            if not policy:
                raise HTTPException(404)
            client_count = connection.execute(
                "SELECT COUNT(*) FROM clients WHERE policy_id=?", (policy_id,)
            ).fetchone()[0]
            if client_count:
                raise HTTPException(
                    409,
                    "Policy wird noch von mindestens einem Server verwendet und kann nicht geloescht werden",
                )
            deleted = connection.execute(
                "DELETE FROM backup_policies WHERE id=?", (policy_id,)
            ).rowcount
            if deleted != 1:
                raise HTTPException(404)
            policy_name = str(policy["name"])
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            409,
            "Policy wird noch verwendet und kann nicht geloescht werden",
        ) from exc
    audit(request, "policy.delete", policy_name, f"policy_id={policy_id}", user_id=user["id"])
    return RedirectResponse(
        f"/policies?message={quote('Backup-Policy wurde gelöscht')}", status_code=303
    )


@app.post("/policies/{policy_id}/paths")
def policy_path_add(
    request: Request,
    policy_id: int,
    source_path: str = Form(...),
    target_name: str = Form(...),
    mode: str = Form(...),
    csrf_token: str = Form(...),
):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    source_path, target_name, mode = validated_policy_path(source_path, target_name, mode)
    try:
        with db() as connection:
            if not connection.execute("SELECT 1 FROM backup_policies WHERE id=?", (policy_id,)).fetchone():
                raise HTTPException(404)
            order = connection.execute(
                "SELECT COALESCE(MAX(sort_order),0)+10 FROM policy_paths WHERE policy_id=?", (policy_id,)
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO policy_paths(policy_id,source_path,target_name,mode,sort_order) VALUES(?,?,?,?,?)",
                (policy_id, source_path, target_name, mode, order),
            )
            connection.execute("UPDATE backup_policies SET updated_at=? WHERE id=?", (now_iso(), policy_id))
            connection.execute(
                "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE policy_id=?",
                (now_iso(), policy_id),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Quellpfad oder Zielname existiert in dieser Policy bereits")
    audit(request, "policy.path_add", str(policy_id), f"{source_path} mode={mode}", user_id=user["id"])
    return RedirectResponse(f"/policies/{policy_id}", status_code=303)


@app.post("/policies/{policy_id}/paths/{path_id}/delete")
def policy_path_delete(request: Request, policy_id: int, path_id: int, csrf_token: str = Form(...)):
    user = require_user(request, admin=True)
    verify_csrf(user, csrf_token)
    with db() as connection:
        deleted = connection.execute(
            "DELETE FROM policy_paths WHERE id=? AND policy_id=?", (path_id, policy_id)
        ).rowcount
        connection.execute("UPDATE backup_policies SET updated_at=? WHERE id=?", (now_iso(), policy_id))
        connection.execute(
            "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE policy_id=?",
            (now_iso(), policy_id),
        )
    if not deleted:
        raise HTTPException(404)
    audit(request, "policy.path_delete", str(policy_id), f"path_id={path_id}", user_id=user["id"])
    return RedirectResponse(f"/policies/{policy_id}", status_code=303)


@app.get("/clients/new", response_class=HTMLResponse)
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


@app.post("/clients/new", response_class=HTMLResponse)
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


@app.get("/clients/{client_id}", response_class=HTMLResponse)
def client_detail(request: Request, client_id: int):
    require_user(request)
    with db() as connection:
        client = connection.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        events = connection.execute("SELECT * FROM status_events WHERE client_id=? ORDER BY id DESC LIMIT 20", (client_id,)).fetchall()
        active_deployment = connection.execute(
            "SELECT expires_at FROM deployment_tokens WHERE client_id=? AND used_at IS NULL "
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
            "commands": commands,
            "run_logs": run_logs,
            "active_command": dict(active_command) if active_command else None,
            "agent_online": agent_online,
            "backup_running": backup_running,
            "policy": dict(policy) if policy else None,
            "policy_paths": policy_paths,
            "policy_mail_summary": policy_mail_summary(policy) if policy else "unbekannt",
            "policies": policies,
            "schedule": schedule_state,
            "account_exists": system_account_exists(client["username"]),
            "home_exists": Path(client["home_path"]).is_dir(),
            "message": request.query_params.get("message", ""),
        },
    )


@app.post("/clients/{client_id}/agent-config")
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


@app.get("/clients/{client_id}/logs/{log_id}", response_class=HTMLResponse)
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


@app.post("/clients/{client_id}/policy")
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


@app.post("/clients/{client_id}/delete")
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


@app.post("/clients/{client_id}/backup/trigger")
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
        client = connection.execute("SELECT * FROM clients WHERE id=? AND active=1", (client_id,)).fetchone()
        if not client:
            raise HTTPException(404)
        if not client["agent_token_hash"]:
            raise HTTPException(409, "Client muss zuerst onboarded werden")
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


@app.post("/clients/{client_id}/token", response_class=HTMLResponse)
def create_deployment_token(
    request: Request,
    client_id: int,
    csrf_token: str = Form(...),
    run_initial_backup: str | None = Form(None),
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
        connection.execute(
            "UPDATE clients SET run_initial_backup=? WHERE id=?",
            (start_immediately, client_id),
        )
        connection.execute("DELETE FROM deployment_tokens WHERE client_id=? AND used_at IS NULL", (client_id,))
        connection.execute(
            "INSERT INTO deployment_tokens(token_hash,client_id,token_ciphertext,expires_at,created_by,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                token_hash(raw),
                client_id,
                encrypt_deployment_token(raw),
                now_ts() + minutes * 60,
                user["id"],
                now_iso(),
            ),
        )
        client = connection.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    audit(
        request,
        "deployment_token.create",
        client["slug"],
        f"expires={minutes}m initial_backup={start_immediately}",
    )
    return RedirectResponse(f"/clients/{client_id}/deployment", status_code=303)


@app.get("/clients/{client_id}/deployment", response_class=HTMLResponse)
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
    if token:
        command = build_deployment_command(decrypt_deployment_token(token["token_ciphertext"]))
        expires_at = datetime.fromtimestamp(token["expires_at"], timezone.utc).astimezone().strftime("%d.%m.%Y %H:%M:%S %Z")
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
        },
    )


@app.post("/clients/{client_id}/deployment/revoke")
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


def agent_script_asset() -> tuple[str, bytes]:
    """Return digest and content of the agent script, re-reading it when it changed."""
    global AGENT_SCRIPT_CACHE
    path = Path(CONFIG["paths"]["backup_script"])
    stamp = path.stat()
    signature = (stamp.st_mtime_ns, stamp.st_size)
    with AGENT_SCRIPT_LOCK:
        cached = AGENT_SCRIPT_CACHE
        if cached and cached[0] == signature:
            return cached[1], cached[2]
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        AGENT_SCRIPT_CACHE = (signature, digest, content)
    return digest, content


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


@app.get("/bootstrap", response_class=PlainTextResponse)
def bootstrap(request: Request):
    raw = bearer(request)
    _, client = deployment_for_token(raw)
    source = Path(CONFIG["paths"]["bootstrap_script"]).read_text(encoding="utf-8")
    prefix = (
        f"PORTAL_URL = {str(application_settings()['public_base_url']).rstrip('/')!r}\n"
        f"DEPLOYMENT_TOKEN = {raw!r}\nCLIENT_SLUG = {client['slug']!r}\n"
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
    return f'''[backup]\nssh_target = "{alias}"\nexpected_source_hostname = "{source_hostname}"\nexpected_ssh_hostname = "{onboarding['fqdn']}"\nexpected_ssh_user = "{client['username']}"\nexpected_ssh_port = {int(onboarding['backup_ssh_port'])}\nexpected_remote_hostname = "{onboarding['remote_hostname']}"\nexpected_remote_home = "{client['home_path']}"\npolicy_id = {int(policy['id'])}\npolicy_name = {json.dumps(policy['name'])}\nconfig_version = {int(client['agent_config_version'])}\nmariadb_available = {str(has_mariadb).lower()}\nmariadb_enabled = {str(mariadb_databases or mariadb_users).lower()}\nmariadb_databases_enabled = {str(mariadb_databases).lower()}\nmariadb_users_enabled = {str(mariadb_users).lower()}\nmin_remote_free_bytes = {int(onboarding['min_remote_free_bytes'])}\ndatabase_split_threshold_bytes = {int(onboarding['database_split_threshold_bytes'])}\nstream_attempts = 2\nrsync_attempts = 3\nzstd_level = 3\nssh_control_path = "/run/raven-backup-ssh-%C"\nlocal_lock_path = "/run/raven-backup-agent-{client['slug']}.lock"\nstate_path = "/var/lib/raven-backup/agent-{client['slug']}.json"\n{empty_sources_config}\n{path_config}\n[schedule]\nhour = {int(policy['schedule_hour'])}\nminute = {int(policy['schedule_minute'])}\ninterval_hours = {int(policy['interval_hours'])}\n\n[notifications]\nmail_on_success = {str(mail_on_success).lower()}\nmail_on_failure = {str(mail_on_failure).lower()}\nmail_on_skipped = {str(mail_on_skipped).lower()}\n\n[logging]\nlevel = {json.dumps(client['agent_log_level'])}\nlocal_enabled = {str(bool(client['agent_log_local'])).lower()}\nportal_enabled = {str(bool(client['agent_log_portal'])).lower()}\ninclude_traceback = {str(bool(client['agent_log_traceback'])).lower()}\nportal_max_bytes = {int(client['agent_log_max_bytes'])}\n\n[status]\nenabled = true\nendpoint = "{portal_url}/api/agent/status"\npoll_endpoint = "{portal_url}/api/agent/poll"\ncommand_endpoint = "{portal_url}/api/agent/commands"\nlog_endpoint = "{portal_url}/api/agent/logs"\ntoken = "{agent_token}"\ntimeout_seconds = 15\n\n[smtp]\nhost = "{smtp['host']}"\nport = {int(smtp['port'])}\nusername = "{smtp['username']}"\npassword = "{smtp['password']}"\nfrom_address = "{smtp['from_address']}"\nto = {to_addresses}\nstarttls = false\ntimeout_seconds = {int(smtp.get('timeout_seconds', 20))}\n'''


@app.post("/api/onboard/register")
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
    audit(request, "client.onboard", client["slug"], f"source={source_hostname}")
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


@app.post("/api/agent/poll")
async def agent_poll(request: Request):
    raw_agent_token = bearer(request)
    client = authenticated_agent(request)
    try:
        data = await request.json()
    except Exception:
        data = {}
    reported_hostname = str(data.get("hostname", "")).strip()
    if reported_hostname and client["source_hostname"] and reported_hostname != client["source_hostname"]:
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
            "UPDATE clients SET last_poll_at=?,mariadb_available=?,agent_script_sha256=? WHERE id=?",
            (now_iso(), reported_mariadb, reported_script_sha256, client["id"]),
        )
        connection.execute(
            "UPDATE backup_commands SET status='queued',claimed_at=NULL,message='Claim timeout; erneut freigegeben' "
            "WHERE client_id=? AND status='claimed' AND claimed_at<?",
            (client["id"], claimed_cutoff),
        )
        command = connection.execute(
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


@app.post("/api/agent/commands/{command_id}")
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


@app.post("/api/agent/status")
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


@app.post("/api/agent/logs")
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


@app.get("/users", response_class=HTMLResponse)
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


@app.post("/users", response_class=HTMLResponse)
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


@app.post("/users/{user_id}/notifications")
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


@app.post("/users/{user_id}/toggle")
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


@app.post("/users/{user_id}/password")
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
