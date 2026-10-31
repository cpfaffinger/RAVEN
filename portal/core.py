"""Configuration, constants, database, time and crypto helpers, and settings access."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import logging
import os
import pwd
import re
import secrets
import sqlite3
import stat as statlib
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from cryptography.fernet import Fernet, InvalidToken

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

AGENT_SCRIPT_LOCK = threading.Lock()
AGENT_SCRIPT_CACHE: tuple[tuple[int, int], str, bytes] | None = None

LOG = logging.getLogger("backup-portal")


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


def checker_cleanup_configuration() -> dict[str, Any]:
    """Read non-secret cleanup/storage defaults retained in the checker TOML."""
    defaults: dict[str, Any] = {
        "enabled": True,
        "run_hour": 23,
        "snapshot_retention_days": 7,
        "minimum_snapshots_to_keep": 2,
        "incomplete_snapshot_retention_hours": 48,
        "legacy_file_retention_days": 5,
        "minimum_free_percent": 15.0,
    }
    try:
        with CHECKER_CONFIG_PATH.open("rb") as handle:
            checker_config = tomllib.load(handle)
        cleanup = checker_config.get("cleanup", {})
        storage = checker_config.get("storage", {})
        if isinstance(cleanup, dict):
            for key in (
                "enabled", "run_hour", "snapshot_retention_days", "minimum_snapshots_to_keep",
                "incomplete_snapshot_retention_hours", "legacy_file_retention_days",
            ):
                if key in cleanup:
                    defaults[key] = cleanup[key]
        if isinstance(storage, dict) and "minimum_free_percent" in storage:
            defaults["minimum_free_percent"] = storage["minimum_free_percent"]
    except (FileNotFoundError, OSError, ValueError, tomllib.TOMLDecodeError):
        pass
    defaults["snapshot_retention_days"] = max(1, min(3650, int(defaults["snapshot_retention_days"])))
    defaults["minimum_snapshots_to_keep"] = max(1, min(100, int(defaults["minimum_snapshots_to_keep"])))
    defaults["run_hour"] = max(0, min(23, int(defaults["run_hour"])))
    defaults["minimum_free_percent"] = max(0.0, min(100.0, float(defaults["minimum_free_percent"])))
    return defaults


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
              storage_bytes INTEGER,
              storage_checked_at TEXT,
              storage_error TEXT NOT NULL DEFAULT '',
              last_event TEXT, last_event_at TEXT, last_success_at TEXT,
              last_poll_at TEXT, last_payload TEXT,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS deployment_tokens (
              token_hash TEXT PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
              token_ciphertext TEXT, expires_at INTEGER NOT NULL, used_at TEXT,
              rotate_ssh_key INTEGER NOT NULL DEFAULT 0,
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
              cleanup_enabled INTEGER NOT NULL DEFAULT 1,
              retention_days INTEGER NOT NULL DEFAULT 7,
              minimum_snapshots_to_keep INTEGER NOT NULL DEFAULT 2,
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
            CREATE TABLE IF NOT EXISTS mirror_targets (
              id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
              host TEXT NOT NULL, ssh_port INTEGER NOT NULL DEFAULT 22,
              username TEXT NOT NULL, remote_path TEXT NOT NULL,
              private_key_ciphertext TEXT NOT NULL DEFAULT '',
              host_key TEXT NOT NULL DEFAULT '',
              rsync_options TEXT NOT NULL DEFAULT '-a --delete --stats',
              strategy TEXT NOT NULL DEFAULT 'latest',
              interval_hours INTEGER NOT NULL DEFAULT 24,
              retention_days INTEGER NOT NULL DEFAULT 0,
              enabled INTEGER NOT NULL DEFAULT 1,
              next_run_at TEXT,
              last_status TEXT, last_run_at TEXT, last_message TEXT,
              total_bytes INTEGER, free_bytes INTEGER, space_checked_at TEXT,
              updated_by INTEGER REFERENCES users(id),
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mirror_runs (
              id INTEGER PRIMARY KEY,
              target_id INTEGER NOT NULL REFERENCES mirror_targets(id) ON DELETE CASCADE,
              mode TEXT NOT NULL CHECK(mode IN ('scheduled','manual')),
              status TEXT NOT NULL CHECK(status IN ('queued','running','success','failure','interrupted')),
              requested_by INTEGER REFERENCES users(id), requested_at TEXT NOT NULL,
              started_at TEXT, finished_at TEXT, exit_code INTEGER,
              transferred_bytes INTEGER, summary TEXT, output TEXT
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
            CREATE TABLE IF NOT EXISTS policy_cleanup_runs (
              id INTEGER PRIMARY KEY,
              policy_id INTEGER REFERENCES backup_policies(id) ON DELETE SET NULL,
              policy_name TEXT NOT NULL,
              dry_run INTEGER NOT NULL DEFAULT 0,
              status TEXT NOT NULL CHECK(status IN ('queued','running','success','error','interrupted')),
              requested_by INTEGER REFERENCES users(id), requested_at TEXT NOT NULL,
              started_at TEXT, finished_at TEXT, exit_code INTEGER,
              reclaimed_bytes INTEGER, summary TEXT, output TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_status_client_time ON status_events(client_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(id DESC);
            CREATE INDEX IF NOT EXISTS idx_commands_client_status ON backup_commands(client_id,status,id);
            CREATE INDEX IF NOT EXISTS idx_run_logs_client_time ON backup_run_logs(client_id,id DESC);
            CREATE INDEX IF NOT EXISTS idx_checker_runs_status ON checker_runs(status,id);
            CREATE INDEX IF NOT EXISTS idx_policy_cleanup_runs_status ON policy_cleanup_runs(status,id);
            CREATE INDEX IF NOT EXISTS idx_policy_cleanup_runs_policy ON policy_cleanup_runs(policy_id,id DESC);
            CREATE INDEX IF NOT EXISTS idx_mirror_runs_target ON mirror_runs(target_id,id DESC);
            CREATE INDEX IF NOT EXISTS idx_mirror_runs_status ON mirror_runs(status,id);
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
        if "rotate_ssh_key" not in token_columns:
            connection.execute("ALTER TABLE deployment_tokens ADD COLUMN rotate_ssh_key INTEGER NOT NULL DEFAULT 0")
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
            "storage_bytes": "INTEGER",
            "storage_checked_at": "TEXT",
            "storage_error": "TEXT NOT NULL DEFAULT ''",
            "last_success_at": "TEXT",
            "reported_hostname": "TEXT",
            "reported_hostname_at": "TEXT",
        }
        for column, definition in client_column_defaults.items():
            if column not in client_columns:
                connection.execute(f"ALTER TABLE clients ADD COLUMN {column} {definition}")
        if "last_success_at" not in client_columns:
            connection.execute(
                "UPDATE clients SET last_success_at="
                "(SELECT MAX(created_at) FROM status_events WHERE client_id=clients.id AND event='success')"
            )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS webauthn_credentials ("
            "id INTEGER PRIMARY KEY, "
            "user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, "
            "credential_id TEXT UNIQUE NOT NULL, public_key BLOB NOT NULL, algorithm INTEGER NOT NULL, "
            "sign_count INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL, aaguid TEXT NOT NULL DEFAULT '', "
            "transports TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, last_used_at TEXT)"
        )
        user_columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        if "webauthn_handle" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN webauthn_handle TEXT")
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
        # Existing policies follow their MariaDB choice: one that backs up
        # databases takes PostgreSQL along, one that deliberately skips them
        # keeps doing so. The agent only dumps instances it actually finds.
        if "postgresql_databases_enabled" not in policy_columns:
            connection.execute(
                "ALTER TABLE backup_policies ADD COLUMN postgresql_databases_enabled INTEGER NOT NULL DEFAULT 1"
            )
            connection.execute("UPDATE backup_policies SET postgresql_databases_enabled=mariadb_databases_enabled")
        if "postgresql_roles_enabled" not in policy_columns:
            connection.execute(
                "ALTER TABLE backup_policies ADD COLUMN postgresql_roles_enabled INTEGER NOT NULL DEFAULT 1"
            )
            connection.execute("UPDATE backup_policies SET postgresql_roles_enabled=mariadb_users_enabled")
        migrate_policy_schedule(connection, policy_columns, client_columns, portal_defaults)
        migrate_policy_notifications(connection, policy_columns, client_columns)
        cleanup_defaults = checker_cleanup_configuration()
        if "cleanup_enabled" not in policy_columns:
            connection.execute(
                "ALTER TABLE backup_policies ADD COLUMN cleanup_enabled INTEGER NOT NULL DEFAULT "
                f"{1 if cleanup_defaults['enabled'] else 0}"
            )
        if "retention_days" not in policy_columns:
            connection.execute(
                "ALTER TABLE backup_policies ADD COLUMN retention_days INTEGER NOT NULL DEFAULT "
                f"{int(cleanup_defaults['snapshot_retention_days'])}"
            )
        if "minimum_snapshots_to_keep" not in policy_columns:
            connection.execute(
                "ALTER TABLE backup_policies ADD COLUMN minimum_snapshots_to_keep INTEGER NOT NULL DEFAULT "
                f"{int(cleanup_defaults['minimum_snapshots_to_keep'])}"
            )
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
        mirror_columns = {row[1] for row in connection.execute("PRAGMA table_info(mirror_targets)")}
        if "strategy" not in mirror_columns:
            # Existing targets keep replicating the whole store until the
            # operator switches them; only new ones start with the latest runs.
            connection.execute("ALTER TABLE mirror_targets ADD COLUMN strategy TEXT NOT NULL DEFAULT 'full'")
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


def format_size(value: int | None) -> str:
    if value is None:
        return "–"
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(amount) < 1024 or unit == "PB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.2f} {unit}"
        amount /= 1024
    return str(value)


def parsed_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
    except (TypeError, ValueError):
        return None


def system_account_exists(username: str) -> bool:
    try:
        pwd.getpwnam(str(username))
    except KeyError:
        return False
    return True


def client_already_deployed(client: sqlite3.Row) -> bool:
    """True once a source server holds an agent or key for this client.

    Imported accounts were provisioned outside the portal and already carry a
    key in authorized_keys, so they count as deployed as well.
    """
    return bool(client["agent_token_hash"]) or bool(client["imported"])


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
