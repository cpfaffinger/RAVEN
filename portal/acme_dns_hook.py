#!/usr/bin/env python3
"""Certbot DNS-01 hook with persistent, portal-readable challenge state."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from domain_config import resolve_domain_config

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


DEFAULT_STATE_DIR = Path("/var/lib/backup-portal/acme")
DEFAULT_CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"


class CloudflareAPIError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_state_dir(raw: str) -> Path:
    path = Path(raw).resolve()
    if not path.is_absolute() or path == Path("/"):
        raise ValueError("ungueltiges ACME-State-Verzeichnis")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def state_file(state_dir: Path) -> Path:
    return state_dir / "challenges.json"


def load_state(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("challenges"), list):
            return data
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        pass
    return {"version": 1, "updated_at": now_iso(), "challenges": []}


def atomic_write(path: Path, data: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def mutate_state(state_dir: Path, callback: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    lock_path = state_dir / "challenges.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        with os.fdopen(descriptor, "r+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            path = state_file(state_dir)
            state = load_state(path)
            callback(state)
            state["updated_at"] = now_iso()
            state["challenges"] = list(state.get("challenges", []))[-50:]
            atomic_write(path, state)
            return state
    finally:
        # fdopen owns and closes the descriptor on the normal path.
        pass


def challenge_identifier(identifier: str, validation: str) -> str:
    return hashlib.sha256(f"{identifier}\0{validation}".encode()).hexdigest()[:24]


def dns_name(identifier: str) -> str:
    normalized = identifier.removeprefix("*.").rstrip(".")
    return f"_acme-challenge.{normalized}"


def find_challenge(state: dict[str, Any], challenge_id: str) -> dict[str, Any] | None:
    return next((item for item in state.get("challenges", []) if item.get("id") == challenge_id), None)


def query_txt(name: str, resolver: str) -> list[str]:
    command = ["/usr/bin/dig", "+time=4", "+tries=1", "+short", "TXT", name]
    if resolver and resolver != "system":
        command.append(f"@{resolver}")
    process = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    if process.returncode != 0:
        return []
    values: list[str] = []
    for line in process.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parts = shlex.split(line)
            values.append("".join(parts) if parts else line.strip('"'))
        except ValueError:
            values.append(line.strip('"'))
    return values


def environment_challenge() -> tuple[str, str]:
    identifier = os.environ.get("CERTBOT_IDENTIFIER") or os.environ.get("CERTBOT_DOMAIN") or ""
    validation = os.environ.get("CERTBOT_VALIDATION", "")
    if not identifier or not validation:
        raise RuntimeError("CERTBOT_IDENTIFIER/CERTBOT_VALIDATION fehlen")
    return identifier, validation


def load_acme_config(path: str) -> dict[str, Any]:
    if not path:
        return {}
    with Path(path).open("rb") as handle:
        config = tomllib.load(handle)
    acme = config.get("acme", {})
    return acme if isinstance(acme, dict) else {}


def load_cloudflare_credentials(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 64 * 1024:
        raise RuntimeError("Cloudflare-Credentials-Datei ist unerwartet gross")
    if path.suffix.lower() == ".toml":
        with path.open("rb") as handle:
            credentials = tomllib.load(handle).get("cloudflare", {})
        if not isinstance(credentials, dict):
            raise RuntimeError("[cloudflare] fehlt in der Credentials-Datei")
        return credentials

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    token = values.get("dns_cloudflare_api_token", "")
    if not token:
        raise RuntimeError(
            "Cloudflare-Credentials muessen api_token in TOML oder "
            "dns_cloudflare_api_token im Certbot-INI-Format enthalten"
        )
    return {"api_token": token}


def load_database_cloudflare_settings(config: dict[str, Any]) -> dict[str, Any]:
    database = config.get("database", {})
    security = config.get("security", {})
    if not isinstance(database, dict) or not isinstance(security, dict) or not database.get("path"):
        return {}
    secret = str(security.get("session_secret", ""))
    if len(secret) < 32:
        raise RuntimeError("Portal-Master-Secret fehlt fuer Cloudflare-Entschluesselung")
    from cryptography.fernet import Fernet, InvalidToken

    database_path = Path(str(database["path"]))
    connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True, timeout=30)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute("SELECT * FROM acme_settings WHERE id=1").fetchone()
    finally:
        connection.close()
    if not row:
        return {}
    ciphertext = str(row["cloudflare_token_ciphertext"] or "")
    token = ""
    if ciphertext:
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
        try:
            token = Fernet(key).decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError("Cloudflare API-Token in SQLite kann nicht entschluesselt werden") from exc
    return {
        "api_token": token,
        "zone_id": str(row["cloudflare_zone_id"] or ""),
        "ttl": int(row["cloudflare_ttl"]),
    }


def cloudflare_settings(path: str) -> dict[str, Any] | None:
    raw_config: dict[str, Any] = {}
    if path:
        config_path = Path(path)
        if config_path.suffix.lower() != ".toml":
            settings = load_cloudflare_credentials(config_path)
            if len(str(settings.get("api_token", ""))) < 20:
                raise RuntimeError("Cloudflare API-Token fehlt oder ist zu kurz")
            return settings
        with config_path.open("rb") as handle:
            raw_config = tomllib.load(handle)
        direct = raw_config.get("cloudflare")
        if isinstance(direct, dict):
            settings = direct
            token = str(settings.get("api_token", ""))
            if len(token) < 20:
                raise RuntimeError("Cloudflare API-Token fehlt oder ist zu kurz")
            return settings
    acme = raw_config.get("acme", {}) if raw_config else load_acme_config(path)
    if not isinstance(acme, dict):
        acme = {}
    if acme.get("mode") != "dns-cloudflare":
        return None
    settings = acme.get("cloudflare", {})
    if not isinstance(settings, dict):
        raise RuntimeError("[acme.cloudflare] fehlt")
    settings = dict(settings)
    resolved_domain = resolve_domain_config(raw_config)
    settings["domain"] = str(resolved_domain["fqdn"])
    settings["zone_name"] = str(resolved_domain["tld"])
    database_settings = load_database_cloudflare_settings(raw_config)
    if database_settings:
        settings = {**settings, **database_settings}
    credentials_file = str(settings.get("credentials_file", ""))
    if not database_settings and credentials_file:
        credentials = load_cloudflare_credentials(Path(credentials_file))
        settings = {**settings, **credentials}
    token = str(settings.get("api_token", ""))
    if len(token) < 20:
        raise RuntimeError("Cloudflare API-Token fehlt oder ist zu kurz")
    return settings


def cloudflare_request(
    settings: dict[str, Any], method: str, endpoint: str, payload: dict[str, Any] | None = None,
    query: dict[str, str] | None = None,
) -> dict[str, Any]:
    base = str(settings.get("api_base", DEFAULT_CLOUDFLARE_API)).rstrip("/")
    url = base + endpoint
    if query:
        url += "?" + urlencode(query)
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {settings['api_token']}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "RAVEN-ACME/1.0",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            data = json.loads(response.read(1024 * 1024).decode("utf-8"))
    except HTTPError as exc:
        try:
            detail = exc.read(65536).decode("utf-8", errors="replace")
        except OSError:
            detail = ""
        raise CloudflareAPIError(f"Cloudflare HTTP {exc.code}: {detail[:1000]}", exc.code) from exc
    except (URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CloudflareAPIError(f"Cloudflare API nicht erreichbar: {type(exc).__name__}: {exc}") from exc
    if not isinstance(data, dict) or not data.get("success"):
        errors = data.get("errors", []) if isinstance(data, dict) else []
        raise CloudflareAPIError(f"Cloudflare API-Fehler: {json.dumps(errors, ensure_ascii=False)[:1000]}")
    return data


def cloudflare_zone(settings: dict[str, Any], identifier: str) -> tuple[str, str]:
    configured_id = str(settings.get("zone_id", "")).strip()
    configured_name = str(settings.get("zone_name", "")).strip().rstrip(".")
    if configured_id:
        return configured_id, configured_name or identifier.removeprefix("*.").rstrip(".")

    labels = identifier.removeprefix("*.").rstrip(".").split(".")
    for offset in range(0, max(0, len(labels) - 1)):
        candidate = ".".join(labels[offset:])
        response = cloudflare_request(
            settings,
            "GET",
            "/zones",
            query={"name": candidate, "status": "active", "per_page": "1"},
        )
        result = response.get("result", [])
        if isinstance(result, list) and result:
            zone_id = str(result[0].get("id", ""))
            zone_name = str(result[0].get("name", candidate))
            if zone_id:
                return zone_id, zone_name
    raise CloudflareAPIError("Keine aktive Cloudflare-Zone fuer den Zertifikatsnamen gefunden")


def cloudflare_create_txt(
    settings: dict[str, Any], identifier: str, name: str, value: str,
) -> tuple[str, str, str]:
    zone_id, zone_name = cloudflare_zone(settings, identifier)
    ttl = int(settings.get("ttl", 60))
    if ttl != 1 and not 60 <= ttl <= 86400:
        raise ValueError("Cloudflare TXT TTL muss 1 oder 60 bis 86400 sein")
    response = cloudflare_request(
        settings,
        "POST",
        f"/zones/{zone_id}/dns_records",
        payload={
            "type": "TXT",
            "name": name,
            "content": value,
            "ttl": ttl,
            "comment": "RAVEN ACME DNS-01 (automatic cleanup)",
        },
    )
    result = response.get("result", {})
    record_id = str(result.get("id", "")) if isinstance(result, dict) else ""
    if not record_id:
        raise CloudflareAPIError("Cloudflare lieferte keine DNS-Record-ID")
    return zone_id, zone_name, record_id


def cloudflare_delete_txt(settings: dict[str, Any], zone_id: str, record_id: str) -> None:
    try:
        cloudflare_request(settings, "DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
    except CloudflareAPIError as exc:
        if exc.status != 404:
            raise


def auth(args: argparse.Namespace) -> int:
    identifier, validation = environment_challenge()
    state_dir = safe_state_dir(args.state_dir)
    challenge_id = challenge_identifier(identifier, validation)
    record_name = dns_name(identifier)
    resolvers = [item.strip() for item in args.resolvers.split(",") if item.strip()] or ["system"]
    created_at = now_iso()
    deadline_epoch = time.time() + args.timeout
    cloudflare = cloudflare_settings(args.config)

    def create(state: dict[str, Any]) -> None:
        existing = find_challenge(state, challenge_id)
        entry = {
            "id": challenge_id,
            "identifier": identifier,
            "record_type": "TXT",
            "record_name": record_name,
            "record_value": validation,
            "status": "creating_dns" if cloudflare else "waiting_dns",
            "created_at": created_at,
            "deadline_at": datetime.fromtimestamp(deadline_epoch, timezone.utc).isoformat(),
            "resolvers": resolvers,
            "seen_by": [],
            "last_checked_at": None,
            "cleanup_required": False,
            "provider": "cloudflare" if cloudflare else "manual",
        }
        if existing:
            existing.update(entry)
        else:
            state.setdefault("challenges", []).append(entry)

    mutate_state(state_dir, create)
    if cloudflare:
        try:
            zone_id, zone_name, record_id = cloudflare_create_txt(cloudflare, identifier, record_name, validation)
        except Exception as exc:
            def api_failure(state: dict[str, Any]) -> None:
                entry = find_challenge(state, challenge_id)
                if entry:
                    entry["status"] = "api_error"
                    entry["finished_at"] = now_iso()
                    entry["provider_error"] = f"{type(exc).__name__}: {exc}"[:2000]
            mutate_state(state_dir, api_failure)
            raise

        def api_created(state: dict[str, Any]) -> None:
            entry = find_challenge(state, challenge_id)
            if entry:
                entry.update(
                    {
                        "status": "waiting_dns",
                        "cloudflare_zone_id": zone_id,
                        "cloudflare_zone_name": zone_name,
                        "cloudflare_record_id": record_id,
                        "provider_created_at": now_iso(),
                    }
                )
        mutate_state(state_dir, api_created)
    print("", flush=True)
    print("=== LET'S ENCRYPT DNS-01 CHALLENGE ===", flush=True)
    print(f"TXT-Name : {record_name}", flush=True)
    print(f"TXT-Wert : {validation}", flush=True)
    if cloudflare:
        print("Cloudflare: TXT-Eintrag wurde automatisch angelegt.", flush=True)
    print(f"Warte bis zu {args.timeout} Sekunden auf DNS-Propagation ...", flush=True)
    print("Der gleiche Datensatz ist im Portal unter Zertifikate sichtbar.", flush=True)
    print("", flush=True)

    while time.time() < deadline_epoch:
        seen_by: list[str] = []
        observations: dict[str, list[str]] = {}
        for resolver in resolvers:
            try:
                values = query_txt(record_name, resolver)
            except (OSError, subprocess.TimeoutExpired):
                values = []
            observations[resolver] = values
            if validation in values:
                seen_by.append(resolver)

        propagated = len(seen_by) == len(resolvers)

        def update(state: dict[str, Any]) -> None:
            entry = find_challenge(state, challenge_id)
            if not entry:
                return
            entry["seen_by"] = seen_by
            entry["observations"] = observations
            entry["last_checked_at"] = now_iso()
            if propagated:
                entry["status"] = "propagated"
                entry["propagated_at"] = now_iso()

        mutate_state(state_dir, update)
        if propagated:
            print(f"DNS-Propagation bestaetigt ({', '.join(resolvers)}). Certbot faehrt fort.", flush=True)
            return 0
        time.sleep(args.interval)

    def timeout(state: dict[str, Any]) -> None:
        entry = find_challenge(state, challenge_id)
        if entry:
            entry["status"] = "timeout"
            entry["finished_at"] = now_iso()

    mutate_state(state_dir, timeout)
    print(f"DNS-Timeout: TXT {record_name} wurde nicht bei allen Resolvern gefunden.", file=sys.stderr, flush=True)
    return 1


def cleanup(args: argparse.Namespace) -> int:
    identifier, validation = environment_challenge()
    state_dir = safe_state_dir(args.state_dir)
    challenge_id = challenge_identifier(identifier, validation)
    record_name = dns_name(identifier)
    cloudflare = cloudflare_settings(args.config)
    current = load_state(state_file(state_dir))
    current_entry = find_challenge(current, challenge_id) or {}

    cleanup_error = ""
    if cloudflare and current_entry.get("cloudflare_zone_id") and current_entry.get("cloudflare_record_id"):
        try:
            cloudflare_delete_txt(
                cloudflare,
                str(current_entry["cloudflare_zone_id"]),
                str(current_entry["cloudflare_record_id"]),
            )
        except Exception as exc:
            cleanup_error = f"{type(exc).__name__}: {exc}"[:2000]

    def mark(state: dict[str, Any]) -> None:
        entry = find_challenge(state, challenge_id)
        if not entry:
            return
        entry["cleanup_required"] = not bool(cloudflare) or bool(cleanup_error)
        entry["cleanup_requested_at"] = now_iso()
        if cleanup_error:
            entry["status"] = "cleanup_error"
            entry["provider_error"] = cleanup_error
        elif cloudflare:
            entry["status"] = "cleaned"
            entry["cleaned_at"] = now_iso()
        elif entry.get("status") == "propagated":
            entry["status"] = "cleanup_required"

    mutate_state(state_dir, mark)
    if cleanup_error:
        print(f"Cloudflare-Cleanup fehlgeschlagen: {cleanup_error}", file=sys.stderr, flush=True)
        return 1
    if cloudflare:
        print(f"Cloudflare TXT-Eintrag automatisch entfernt: {record_name}", flush=True)
    else:
        print(f"DNS-01 abgeschlossen. TXT-Eintrag kann entfernt werden: {record_name}", flush=True)
    return 0


def cloudflare_check(args: argparse.Namespace) -> int:
    settings = cloudflare_settings(args.config)
    if not settings:
        raise RuntimeError("[acme].mode ist nicht dns-cloudflare")
    response = cloudflare_request(settings, "GET", "/user/tokens/verify")
    result = response.get("result", {})
    if not isinstance(result, dict) or result.get("status") != "active":
        raise CloudflareAPIError("Cloudflare API-Token ist nicht aktiv")
    acme = load_acme_config(args.config)
    domain = str(settings.get("domain") or acme.get("domain", ""))
    zone_id, zone_name = cloudflare_zone(settings, domain)
    cloudflare_request(
        settings,
        "GET",
        f"/zones/{zone_id}/dns_records",
        query={"type": "TXT", "name": dns_name(domain), "per_page": "1"},
    )
    print(f"Cloudflare API OK: zone={zone_name} zone_id={zone_id}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["auth", "cleanup", "cloudflare-check"])
    parser.add_argument("--config", default="")
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    parser.add_argument("--timeout", type=int, default=7200)
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--resolvers", default="1.1.1.1,8.8.8.8")
    args = parser.parse_args()
    if args.timeout < 60 or args.timeout > 86400:
        parser.error("--timeout muss zwischen 60 und 86400 liegen")
    if args.interval < 5 or args.interval > 300:
        parser.error("--interval muss zwischen 5 und 300 liegen")
    if args.action == "auth":
        return auth(args)
    if args.action == "cleanup":
        return cleanup(args)
    return cloudflare_check(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ACME DNS hook failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2)
