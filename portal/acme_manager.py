#!/usr/bin/env python3
"""Request and renew the portal certificate through a managed DNS-01 flow."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

from domain_config import resolve_domain_config
from runtime_config import runtime_config

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


CONFIG_PATH = Path(os.environ.get("BACKUP_PORTAL_CONFIG", "/etc/backup-portal/config.toml"))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def file_digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def promote_pending_domain(config: dict[str, Any]) -> bool:
    database = config.get("database", {})
    if not isinstance(database, dict) or not database.get("path"):
        return False
    connection = sqlite3.connect(str(database["path"]), timeout=30)
    try:
        row = connection.execute(
            "SELECT pending_domain_tld,pending_domain_subdomain,domain_change_pending "
            "FROM portal_settings WHERE id=1"
        ).fetchone()
        if not row or not row[2]:
            return False
        connection.execute(
            "UPDATE portal_settings SET domain_tld=?,domain_subdomain=?,pending_domain_tld='',"
            "pending_domain_subdomain='',domain_change_pending=0,updated_at=? WHERE id=1",
            (row[0], row[1], now_iso()),
        )
        connection.execute(
            "UPDATE clients SET agent_config_version=agent_config_version+1,agent_config_updated_at=? WHERE active=1",
            (now_iso(),),
        )
        connection.commit()
        return True
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="Zertifikat unabhaengig vom Ablauf neu ausstellen")
    args = parser.parse_args()

    with CONFIG_PATH.open("rb") as handle:
        config = tomllib.load(handle)
    config = runtime_config(config, prefer_pending_domain=True)
    acme = config.get("acme", {})
    if acme.get("mode") not in {"dns-manual", "dns-cloudflare"}:
        raise SystemExit("[acme].mode ist weder dns-manual noch dns-cloudflare")

    domain = str(resolve_domain_config(config)["fqdn"])
    email = str(acme["email"])
    state_dir = Path(str(acme.get("state_dir", "/var/lib/backup-portal/acme")))
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    job_path = state_dir / "job.json"
    force_marker = state_dir / "force-request"
    force = args.force or force_marker.exists()

    lock_path = Path(str(acme.get("lock_path", "/run/backup-portal-acme.lock")))
    lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("Ein ACME-Lauf ist bereits aktiv")
    try:
        force_marker.unlink()
    except FileNotFoundError:
        pass

    started_at = now_iso()
    job: dict[str, Any] = {
        "status": "running",
        "mode": "force" if force else "scheduled",
        "domain": domain,
        "started_at": started_at,
        "finished_at": None,
        "certificate_changed": False,
        "message": "Certbot wurde gestartet",
        "output": "",
    }
    atomic_json(job_path, job)

    hook = Path(str(acme.get("hook", "/opt/backup-portal/acme_dns_hook.py")))
    python = Path(str(acme.get("python", sys.executable)))
    timeout = int(acme.get("propagation_timeout_seconds", 7200))
    interval = int(acme.get("poll_interval_seconds", 15))
    resolvers = ",".join(str(item) for item in acme.get("resolvers", ["1.1.1.1", "8.8.8.8"]))
    hook_base = [str(python), str(hook)]
    hook_config = str(CONFIG_PATH)
    hook_options = [
        "--config", hook_config, "--state-dir", str(state_dir), "--timeout", str(timeout),
        "--interval", str(interval), "--resolvers", resolvers,
    ]
    auth_command = shlex.join([*hook_base, "auth", *hook_options])
    cleanup_command = shlex.join([*hook_base, "cleanup", *hook_options])

    certificate = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    before = file_digest(certificate)
    command = [
        str(acme.get("certbot", "/usr/bin/certbot")),
        "certonly",
        "--manual",
        "--preferred-challenges",
        "dns",
        "--manual-auth-hook",
        auth_command,
        "--manual-cleanup-hook",
        cleanup_command,
        "--non-interactive",
        "--agree-tos",
        "--email",
        email,
        "--cert-name",
        domain,
        "--domains",
        domain,
        "--keep-until-expiring",
    ]
    if force:
        command.append("--force-renewal")

    try:
        process = subprocess.run(command, capture_output=True, text=True, errors="replace", check=False)
    except Exception as exc:
        job.update(
            {
                "status": "failure",
                "finished_at": now_iso(),
                "message": f"{type(exc).__name__}: {exc}",
                "output": "",
            }
        )
        atomic_json(job_path, job)
        raise
    combined = (process.stdout + ("\n" if process.stdout and process.stderr else "") + process.stderr).strip()
    output = combined[-20000:]
    after = file_digest(certificate)
    changed = bool(after and after != before)
    job.update(
        {
            "status": "success" if process.returncode == 0 else "failure",
            "finished_at": now_iso(),
            "certificate_changed": changed,
            "message": (
                "Zertifikat wurde ausgestellt und aktiviert"
                if process.returncode == 0 and changed
                else "Zertifikat ist noch gueltig; keine Ausstellung erforderlich"
                if process.returncode == 0
                else f"Certbot endete mit Status {process.returncode}"
            ),
            "output": output,
            "exit_code": process.returncode,
        }
    )
    domain_activated = False
    if process.returncode == 0 and certificate.is_file():
        domain_activated = promote_pending_domain(config)
        if domain_activated:
            job["message"] += "; vorgemerkte Portal-Domain wurde aktiviert"
            job["domain_activated"] = True
    atomic_json(job_path, job)

    if (changed or domain_activated) and subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", "backup-portal.service"], check=False
    ).returncode == 0:
        subprocess.run(["/usr/bin/systemctl", "try-restart", "backup-portal.service"], check=False)
    return process.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ACME manager failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2)
