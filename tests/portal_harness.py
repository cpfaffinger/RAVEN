"""Run the real portal application against a throw-away configuration.

Importing this module builds a temporary root holding the config, the SQLite
database, the home root and every other path the portal may write to, imports
``portal/app.py`` once and removes the root again when the interpreter exits.
Nothing here needs root.

``PortalTestCase`` gives every test an empty database and keeps the application
away from the machine it runs on: the worker loops are replaced by functions
that return at once, a call of ``subprocess.run`` or ``subprocess.Popen`` fails
the test unless the test scripted it, and the helpers that create Linux users or
write below /run are redirected to a scratch directory.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import warnings
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

if os.name != "posix":
    raise unittest.SkipTest("the portal needs POSIX modules; run these tests in WSL")

from fastapi.testclient import TestClient  # noqa: E402


PORTAL_DIR = Path(__file__).resolve().parents[1] / "portal"
WORKER_THREADS = {"backup-scheduler", "checker-worker", "mirror-worker", "storage-worker"}
WORKER_LOOPS = ("scheduler_loop", "checker_loop", "mirror_loop", "storage_loop")
AGENT_SCRIPT = b"#!/usr/bin/env python3\nprint('agent')\n"

_ROOT = tempfile.TemporaryDirectory(prefix="raven-portal-tests-")
atexit.register(_ROOT.cleanup)
ROOT = Path(_ROOT.name)


def _write_config(root: Path) -> Path:
    def path(*parts: str) -> str:
        return json.dumps(str(root.joinpath(*parts)))

    for directory in ("home", "assets", "acme", "scratch"):
        (root / directory).mkdir()
    (root / "assets" / "backup_job.py").write_bytes(AGENT_SCRIPT)
    (root / "assets" / "bootstrap_agent.py").write_text("print('bootstrap')\n", encoding="utf-8")
    config = root / "config.toml"
    config.write_text(
        f"""
[domain]
tld = "raven.test"
subdomain = "backup"

[server]
host = "127.0.0.1"
port = 443
tls_cert = {path("assets", "fullchain.pem")}
tls_key = {path("assets", "privkey.pem")}

[acme]
mode = "dns-cloudflare"
email = "admin@raven.test"
state_dir = {path("acme")}
lock_path = {path("acme", "lock")}
hook = {path("assets", "acme_dns_hook.py")}
python = {path("assets", "python")}
certbot = {path("assets", "certbot")}

[acme.cloudflare]
credentials_file = {path("acme", "cloudflare-acme.toml")}

[database]
path = {path("portal.db")}

[paths]
backup_script = {path("assets", "backup_job.py")}
bootstrap_script = {path("assets", "bootstrap_agent.py")}
checker_state = {path("assets", "state.json")}
home_root = {path("home")}

[checker]
enabled = false
interval_minutes = 60
timeout_seconds = 60
script = {path("assets", "backup_check.py")}
config = {path("assets", "backup-check.toml")}

[onboarding]
username_prefix = "backup_"
backup_ssh_port = 49150
remote_hostname = "backup"
deployment_token_minutes = 15
default_schedule_hour = 2
default_schedule_minute = 0
default_interval_hours = 24
min_remote_free_bytes = 21474836480
database_split_threshold_bytes = 2147483648

[security]
session_hours = 12
session_secret = "{secrets.token_hex(32)}"

[smtp]
enabled = true
host = "smtp.raven.test"
port = 25
from_address = "raven@raven.test"
to = []
""",
        encoding="utf-8",
    )
    return config


def _import_portal(config: Path) -> Any:
    sys.path.insert(0, str(PORTAL_DIR))
    previous = os.environ.get("BACKUP_PORTAL_CONFIG")
    os.environ["BACKUP_PORTAL_CONFIG"] = str(config)
    try:
        import app
    finally:
        if previous is None:
            del os.environ["BACKUP_PORTAL_CONFIG"]
        else:
            os.environ["BACKUP_PORTAL_CONFIG"] = previous
    # The failure paths log on purpose; a test asserts their result instead.
    app.LOG.addHandler(logging.NullHandler())
    app.LOG.propagate = False
    return app


portal_app = _import_portal(_write_config(ROOT))
SCRATCH = ROOT / "scratch"


def hours_ago(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def hours_ahead(hours: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def reset_portal() -> None:
    """Empty the database and the state the application keeps in memory.

    The tables are wiped instead of deleting the file: a connection that is
    still waiting for the garbage collector would remove the -wal file of its
    successor once it closes.
    """
    with closing(sqlite3.connect(portal_app.DB_PATH, timeout=30)) as connection, connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        for (table,) in tables:
            connection.execute(f'DELETE FROM "{table}"')
    portal_app.init_db()
    for entry in portal_app.HOME_ROOT.iterdir():
        shutil.rmtree(entry)
    portal_app.LOGIN_FAILURES.clear()
    portal_app.PASSKEY_FLOWS.clear()
    portal_app.AGENT_SCRIPT_CACHE = None
    for name in ("SCHEDULER_THREAD", "CHECKER_THREAD", "MIRROR_THREAD", "STORAGE_THREAD"):
        setattr(portal_app, name, None)


class PortalClient(TestClient):
    """HTTP client of one browser or agent, talking to the portal over its real host name."""

    csrf_token = ""
    user_id: int | None = None

    def submit(self, path: str, **form: Any) -> Any:
        """Post a form the way the signed-in browser does, CSRF token included."""
        form.setdefault("csrf_token", self.csrf_token)
        return self.post(path, data=form)


def refuse_subprocess(*args: Any, **kwargs: Any) -> None:
    raise AssertionError(f"unexpected subprocess call: {args!r}")


class PortalTestCase(unittest.TestCase):
    def setUp(self) -> None:
        # Both come from the application on every request and bury real findings:
        # connections are left to the garbage collector, and templates still use
        # the old TemplateResponse signature.
        warnings.filterwarnings("ignore", "unclosed database", ResourceWarning)
        warnings.filterwarnings("ignore", ".*`name` is not the first parameter", DeprecationWarning)
        self.addCleanup(self.assert_no_worker_is_running)
        reset_portal()
        self.scratch = Path(tempfile.mkdtemp(dir=SCRATCH))
        self.addCleanup(shutil.rmtree, self.scratch, ignore_errors=True)
        for loop in WORKER_LOOPS:
            self.patch(portal_app, loop, new=lambda: None)
        self.subprocess_run = self.patch(subprocess, "run", side_effect=refuse_subprocess)
        self.subprocess_popen = self.patch(subprocess, "Popen", side_effect=refuse_subprocess)
        self.provisioned = self.patch(
            portal_app, "provision_system_user", side_effect=lambda _username, home: home.mkdir()
        )
        self.discard_credentials = self.patch(portal_app, "discard_stale_mirror_credentials")
        self.patch(portal_app, "write_run_payload", side_effect=self.scratch_payload)
        self.patch(portal_app, "mirror_credentials", side_effect=self.scratch_credentials)
        self.patch(portal_app, "systemd_active", return_value=False)
        self.patch(portal_app, "systemd_unit_details", side_effect=lambda unit: {
            "name": unit, "kind": "systemd", "status": "unknown", "result": "Nicht verfügbar",
            "started_at": "", "finished_at": "", "details": "",
        })

    def assert_no_worker_is_running(self) -> None:
        running = WORKER_THREADS & {thread.name for thread in threading.enumerate()}
        self.assertFalse(running, "worker threads outlived the test")

    def patch(self, target: Any, name: str, **kwargs: Any) -> Any:
        patcher = mock.patch.object(target, name, **kwargs)
        started = patcher.start()
        self.addCleanup(patcher.stop)
        return started

    def scratch_payload(self, name: str, run: Any, payload: dict[str, Any]) -> Path:
        path = self.scratch / f"{name}-{int(run['id'])}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def scratch_credentials(self, target: Any) -> tuple[Path, Path]:
        key = self.scratch / f"key-{int(target['id'])}"
        known_hosts = self.scratch / f"known-hosts-{int(target['id'])}"
        key.write_text("private key\n", encoding="utf-8")
        known_hosts.write_text(str(target["host_key"]) + "\n", encoding="utf-8")
        return key, known_hosts

    # Database access

    def execute(self, sql: str, *params: Any) -> None:
        with closing(portal_app.db()) as connection, connection:
            connection.execute(sql, params)

    def insert(self, table: str, **values: Any) -> int:
        columns = ",".join(values)
        marks = ",".join("?" for _ in values)
        with closing(portal_app.db()) as connection, connection:
            return connection.execute(
                f"INSERT INTO {table}({columns}) VALUES({marks})", tuple(values.values())
            ).lastrowid

    def rows(self, sql: str, *params: Any) -> list[dict[str, Any]]:
        with closing(portal_app.db()) as connection:
            return [dict(row) for row in connection.execute(sql, params).fetchall()]

    def row(self, sql: str, *params: Any) -> dict[str, Any] | None:
        found = self.rows(sql, *params)
        return found[0] if found else None

    def count(self, table: str, where: str = "1=1", *params: Any) -> int:
        return self.rows(f"SELECT COUNT(*) AS n FROM {table} WHERE {where}", *params)[0]["n"]

    # HTTP clients

    def client(self) -> PortalClient:
        client = PortalClient(
            portal_app.app, base_url=f"https://{portal_app.PORTAL_FQDN}", follow_redirects=False
        )
        self.addCleanup(client.close)
        return client

    def session(self, role: str = "admin", *, username: str | None = None, expires_in: int = 3600) -> PortalClient:
        """Return a client with an open session, without paying for a password hash."""
        username = username or f"{role}-user"
        user = self.row("SELECT id FROM users WHERE username=?", username)
        user_id = user["id"] if user else self.add_user(username, role)
        raw = secrets.token_urlsafe(32)
        client = self.client()
        client.csrf_token = secrets.token_urlsafe(32)
        client.user_id = user_id
        self.insert(
            "sessions", token_hash=portal_app.token_hash(raw), user_id=user_id, csrf_token=client.csrf_token,
            expires_at=portal_app.now_ts() + expires_in, created_at=portal_app.now_iso(),
        )
        client.cookies.set("backup_portal_session", raw)
        return client

    # Records

    def add_user(self, username: str, role: str, *, password: str | None = None, active: int = 1) -> int:
        return self.insert(
            "users", username=username, display_name=username, role=role, active=active,
            password_hash=portal_app.hash_password(password) if password else "!",
            created_at=portal_app.now_iso(),
        )

    def default_policy_id(self) -> int:
        return self.row("SELECT id FROM backup_policies WHERE name='Standard Zstd Archive'")["id"]

    def add_policy(self, name: str, **columns: Any) -> int:
        return self.insert(
            "backup_policies", name=name, created_at=portal_app.now_iso(), updated_at=portal_app.now_iso(), **columns
        )

    def add_client(self, slug: str, *, token: str | None = None, **columns: Any) -> SimpleNamespace:
        """Add an onboarded source server and return what its agent knows about itself."""
        token = token or f"agent-token-{slug}"
        username = f"backup_{slug}"
        values: dict[str, Any] = {
            "slug": slug, "username": username, "source_hostname": f"{slug}.raven.test",
            "home_path": str(portal_app.HOME_ROOT / username), "policy_id": self.default_policy_id(),
            "agent_token_hash": portal_app.token_hash(token), "created_at": portal_app.now_iso(),
        }
        values.update(columns)
        client_id = self.insert("clients", **values)
        return SimpleNamespace(
            id=client_id, slug=slug, token=token, hostname=values["source_hostname"],
            headers={"Authorization": f"Bearer {token}"},
        )

    def add_command(self, client_id: int, status: str = "queued", **columns: Any) -> int:
        values: dict[str, Any] = {
            "client_id": client_id, "reason": "manual", "status": status, "requested_at": portal_app.now_iso(),
        }
        values.update(columns)
        return self.insert("backup_commands", **values)

    def add_mirror_target(self, name: str = "box1", **columns: Any) -> int:
        values: dict[str, Any] = {
            "name": name, "host": "mirror.raven.test", "ssh_port": 22, "username": "mirror",
            "remote_path": "/srv/raven", "private_key_ciphertext": portal_app.encrypt_deployment_token("key\n"),
            "host_key": "mirror.raven.test ssh-ed25519 AAAA", "strategy": "latest", "interval_hours": 216,
            "created_at": portal_app.now_iso(), "updated_at": portal_app.now_iso(),
        }
        values.update(columns)
        return self.insert("mirror_targets", **values)

    def add_mirror_run(self, target_id: int, status: str, **columns: Any) -> int:
        values: dict[str, Any] = {
            "target_id": target_id, "mode": "scheduled", "status": status, "requested_at": portal_app.now_iso(),
        }
        values.update(columns)
        return self.insert("mirror_runs", **values)
