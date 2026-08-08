#!/usr/bin/env python3
"""Monitor per-user backups below /home and send stateful SMTP alerts."""

from __future__ import annotations

import argparse
import fnmatch
import html
import json
import os
import pwd
import re
import shutil
import smtplib
import socket
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        raise SystemExit("Python 3.10 oder neuer sowie tomli werden benoetigt")


CONFIG_DISPLAY = "/root/backup-check.toml"
STATUS_DISPLAY = "journalctl -u backup-portal"


@dataclass
class Result:
    user: str
    status: str
    mode: str
    latest: str | None
    age_hours: float | None
    detail: str
    volume_bytes: int | None = None
    previous_volume_bytes: int | None = None
    volume_delta_bytes: int | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/root/backup-check.toml")
    parser.add_argument("--dry-run", action="store_true", help="Pruefen, aber keine Mail senden")
    parser.add_argument("--send-test", action="store_true", help="Nur SMTP-Testmail senden")
    parser.add_argument("--check-smtp", action="store_true", help="SMTP-Anmeldung ohne Mailversand testen")
    parser.add_argument("--smtp-json-file", help="Root-only SMTP-Override aus dem Portal")
    parser.add_argument(
        "--schedule-json-file",
        help="Root-only Fristen je Backup-Benutzer aus dem Portal, abgeleitet aus dem Policy-Intervall",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Vollstaendigen Check ausfuehren und Ergebnis-Mail unabhaengig vom Alarmstatus senden",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def read_json_override(path_value: str, description: str) -> dict[str, Any]:
    override_path = Path(path_value)
    if override_path.is_symlink() or override_path.stat().st_size > 64 * 1024:
        raise ValueError(f"Ungueltige {description}")
    payload = json.loads(override_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{description} muss ein JSON-Objekt sein")
    return payload


def load_config(
    path: str, smtp_json_file: str | None = None, schedule_json_file: str | None = None
) -> dict[str, Any]:
    with open(path, "rb") as handle:
        cfg = tomllib.load(handle)
    if smtp_json_file:
        cfg["smtp"] = read_json_override(smtp_json_file, "SMTP-Override-Datei")
    if schedule_json_file:
        # Deadlines follow the policy interval. An explicit entry in the TOML
        # configuration stays a deliberate exception and keeps precedence.
        portal_ages = read_json_override(schedule_json_file, "Zeitplan-Override-Datei")
        monitor = cfg.setdefault("monitor", {})
        merged = {str(user): float(hours) for user, hours in portal_ages.items()}
        merged.update(dict(monitor.get("max_age_hours_by_user", {})))
        monitor["max_age_hours_by_user"] = merged
    for section in ("monitor", "smtp", "alerts"):
        if section not in cfg:
            raise ValueError(f"Konfigurationsabschnitt [{section}] fehlt")
    return cfg


def local_now() -> datetime:
    return datetime.now().astimezone()


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


def iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).astimezone().isoformat(timespec="seconds")


def ignored(relative: str, patterns: list[str]) -> bool:
    relative = relative.strip("/")
    name = relative.rsplit("/", 1)[-1]
    absolute = "/home/" + relative
    return any(
        fnmatch.fnmatchcase(relative, pattern.strip("/"))
        or fnmatch.fnmatchcase(name, pattern.strip("/"))
        or fnmatch.fnmatchcase(absolute, pattern)
        for pattern in patterns
    )


def folder_has_content(path: Path) -> bool:
    try:
        return next(path.iterdir(), None) is not None
    except OSError:
        return False


def measure_volume_bytes(path: Path, timeout_seconds: float) -> int:
    """Measure logical content size in bytes and count hard-linked paths independently."""
    proc = subprocess.run(
        ["/usr/bin/du", "--summarize", "--bytes", "--count-links", "--apparent-size", "--", str(path)],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if proc.returncode != 0:
        error = proc.stderr.strip() or f"du endete mit Status {proc.returncode}"
        raise RuntimeError(error)
    try:
        return int(proc.stdout.split(maxsplit=1)[0])
    except (IndexError, ValueError) as exc:
        raise RuntimeError(f"ungueltige du-Ausgabe fuer {path}") from exc


def measure_snapshot_volume_bytes(path: Path, timeout_seconds: float) -> int:
    """Prefer policy-aware protected logical bytes from the signed-off manifest."""
    try:
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        value = manifest.get("protected_logical_bytes")
        if isinstance(value, int) and value >= 0:
            return value
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError, AttributeError):
        pass
    return measure_volume_bytes(path, timeout_seconds)


def valid_ok_marker(snapshot: Path, marker_name: str) -> bool:
    try:
        payload = json.loads((snapshot / marker_name).read_text(encoding="utf-8"))
        return payload.get("status") == "ok" and payload.get("run_id") == snapshot.name
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError, AttributeError):
        return False


def remove_snapshot(snapshot: Path, user_home: Path, *, dry_run: bool, timeout: float) -> int:
    resolved_home = user_home.resolve(strict=True)
    resolved = snapshot.resolve(strict=True)
    if resolved.parent != resolved_home or not resolved.name.isdigit():
        raise RuntimeError(f"unsicheres Cleanup-Ziel abgelehnt: {resolved}")
    logical_bytes = measure_volume_bytes(resolved, timeout)
    if not dry_run:
        shutil.rmtree(resolved)
    return logical_bytes


def cleanup_backups(cfg: dict[str, Any], *, dry_run: bool) -> Result | None:
    cleanup = cfg.get("cleanup", {})
    if not bool(cleanup.get("enabled", False)):
        return None
    run_hour = int(cleanup.get("run_hour", 23))
    if not dry_run and local_now().hour != run_hour:
        return None

    mon = cfg["monitor"]
    home_root = Path(mon.get("home_root", "/home"))
    user_glob = str(mon.get("user_glob", "backup_*"))
    marker_name = str(mon.get("ok_marker_name", ".backup-ok"))
    digit_count = int(cleanup.get("snapshot_name_digits", 17))
    snapshot_days = float(cleanup.get("snapshot_retention_days", 7))
    incomplete_hours = float(cleanup.get("incomplete_snapshot_retention_hours", 48))
    minimum_keep = int(cleanup.get("minimum_snapshots_to_keep", 2))
    legacy_days = float(cleanup.get("legacy_file_retention_days", 5))
    legacy_patterns = list(cleanup.get("legacy_file_patterns", ["*.tgz", "*.gz", "*.pst", "*.sql"]))
    delete_empty = bool(cleanup.get("delete_empty_directories", True))
    timeout = float(mon.get("volume_timeout_seconds", 300))
    now_epoch = local_now().timestamp()
    snapshot_cutoff = now_epoch - snapshot_days * 86400
    incomplete_cutoff = now_epoch - incomplete_hours * 3600
    legacy_cutoff = now_epoch - legacy_days * 86400
    removed_snapshots = 0
    removed_incomplete = 0
    removed_files = 0
    removed_empty = 0
    reclaimed_bytes = 0
    errors: list[str] = []

    users = sorted(path for path in home_root.glob(user_glob) if path.is_dir())
    for user_home in users:
        snapshots = [
            child
            for child in user_home.iterdir()
            if child.is_dir() and len(child.name) == digit_count and child.name.isdigit()
        ]
        successful = sorted(
            (child for child in snapshots if valid_ok_marker(child, marker_name)),
            key=lambda path: path.name,
            reverse=True,
        )
        protected = set(successful[:minimum_keep])
        for snapshot in successful[minimum_keep:]:
            try:
                completed_mtime = (snapshot / marker_name).stat().st_mtime
                if snapshot_days > 0 and completed_mtime < snapshot_cutoff:
                    reclaimed_bytes += remove_snapshot(snapshot, user_home, dry_run=dry_run, timeout=timeout)
                    removed_snapshots += 1
            except Exception as exc:
                errors.append(f"{snapshot}: {exc}")
        for snapshot in snapshots:
            if snapshot in protected or snapshot in successful:
                continue
            try:
                if incomplete_hours > 0 and snapshot.stat().st_mtime < incomplete_cutoff:
                    reclaimed_bytes += remove_snapshot(snapshot, user_home, dry_run=dry_run, timeout=timeout)
                    removed_incomplete += 1
            except Exception as exc:
                errors.append(f"{snapshot}: {exc}")

        existing_snapshots = {
            child.name
            for child in user_home.iterdir()
            if child.is_dir() and len(child.name) == digit_count and child.name.isdigit()
        }
        visited_dirs: list[Path] = []
        for root, dirs, files in os.walk(user_home, topdown=True, followlinks=False):
            root_path = Path(root)
            if root_path == user_home:
                dirs[:] = [name for name in dirs if name not in existing_snapshots]
            visited_dirs.append(root_path)
            for filename in files:
                if not any(fnmatch.fnmatchcase(filename, pattern) for pattern in legacy_patterns):
                    continue
                path = root_path / filename
                try:
                    metadata = path.lstat()
                    if stat.S_ISREG(metadata.st_mode) and metadata.st_mtime < legacy_cutoff:
                        reclaimed_bytes += metadata.st_size
                        if not dry_run:
                            path.unlink()
                        removed_files += 1
                except Exception as exc:
                    errors.append(f"{path}: {exc}")
        if delete_empty:
            for directory in reversed(visited_dirs[1:]):
                try:
                    if directory.exists() and not any(directory.iterdir()):
                        if not dry_run:
                            directory.rmdir()
                        removed_empty += 1
                except Exception as exc:
                    errors.append(f"{directory}: {exc}")

    prefix = "Cleanup-Dry-Run" if dry_run else "Cleanup"
    detail = (
        f"{prefix}: {removed_snapshots} erfolgreiche Snapshots, {removed_incomplete} unvollstaendige "
        f"Snapshots, {removed_files} Legacy-Dateien und {removed_empty} leere Ordner; "
        f"logisches Volumen {format_size(reclaimed_bytes)}"
    )
    if errors:
        detail += f"; {len(errors)} Fehler; erster Fehler: {errors[0]}"
    return Result(
        user="BACKUP_TARGET_CLEANUP",
        status="ERROR" if errors else "OK",
        mode="cleanup",
        latest=local_now().isoformat(timespec="seconds"),
        age_hours=0,
        detail=detail,
        volume_bytes=reclaimed_bytes,
    )


def storage_check(cfg: dict[str, Any]) -> Result | None:
    storage = cfg.get("storage", {})
    if not bool(storage.get("enabled", True)):
        return None
    path = Path(str(storage.get("path", cfg["monitor"].get("home_root", "/home"))))
    threshold = float(storage.get("minimum_free_percent", 15))
    usage = shutil.disk_usage(path)
    free_percent = usage.free / usage.total * 100 if usage.total else 0.0
    status = "OK" if free_percent >= threshold else "ERROR"
    detail = (
        f"Speicher auf {path}: {format_size(usage.free)} frei von {format_size(usage.total)} "
        f"({free_percent:.2f}% frei), Alarmgrenze {threshold:.2f}%"
    )
    return Result(
        user="BACKUP_TARGET_STORAGE",
        status=status,
        mode="storage",
        latest=local_now().isoformat(timespec="seconds"),
        age_hours=0,
        detail=detail,
    )


def parse_backup_timestamp(name: str, formats: list[str]) -> datetime | None:
    for fmt in formats:
        try:
            parsed = datetime.strptime(name, fmt)
            return parsed.astimezone()
        except ValueError:
            continue
    return None


def ssh_activity(since_epoch: float, unit: str) -> dict[str, float]:
    """Return latest accepted SSH login per user from journald."""
    command = [
        "/usr/bin/journalctl",
        "-u",
        unit,
        "--since",
        f"@{int(since_epoch)}",
        "--output=json",
        "--no-pager",
    ]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if proc.returncode != 0:
        return {}

    latest: dict[str, float] = {}
    login_re = re.compile(r"Accepted \S+ for (?P<user>[^ ]+) from ")
    for line in proc.stdout.splitlines():
        try:
            item = json.loads(line)
            match = login_re.search(str(item.get("MESSAGE", "")))
            if not match:
                continue
            timestamp = int(item["__REALTIME_TIMESTAMP"]) / 1_000_000
            user = match.group("user")
            latest[user] = max(timestamp, latest.get(user, 0.0))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
    return latest


def evaluate(cfg: dict[str, Any], previous_state: dict[str, Any] | None = None) -> list[Result]:
    mon = cfg["monitor"]
    home_root = Path(mon.get("home_root", "/home"))
    user_glob = str(mon.get("user_glob", "backup_*"))
    max_age = float(mon.get("max_age_hours", 36))
    formats = list(mon.get("timestamp_formats", ["%Y%m%d", "%Y%m%d%H%M", "%Y%m%d%H%M%S"]))
    mirror_names = list(mon.get("mirror_folder_patterns", ["current", "current_copy", "rsync_copy_*"]))
    ignore_patterns = list(mon.get("ignore", []))
    require_nonempty = bool(mon.get("require_nonempty", True))
    check_volume = bool(mon.get("check_volume_change", True))
    volume_timeout = float(mon.get("volume_timeout_seconds", 300))
    marker_name = str(mon.get("ok_marker_name", ".backup-ok"))
    marker_users = list(mon.get("require_ok_file_for_users", []))
    incomplete_grace_hours = float(mon.get("incomplete_grace_hours", 6))
    previous_users = (previous_state or {}).get("users", {})
    age_overrides = mon.get("max_age_hours_by_user", {})
    now = local_now()
    # Mirrors are judged by SSH activity, so the journal window has to cover the
    # longest deadline in play, not only the global default.
    longest_age = max([max_age, *(float(value) for value in age_overrides.values())])
    cutoff = now.timestamp() - longest_age * 3600
    ssh_latest = (
        ssh_activity(cutoff, str(mon.get("ssh_journal_unit", "ssh.service")))
        if mon.get("ssh_activity_for_mirrors", True)
        else {}
    )
    results: list[Result] = []

    users = sorted(path for path in home_root.glob(user_glob) if path.is_dir())
    for user_path in users:
        user = user_path.name
        if ignored(user, ignore_patterns):
            continue
        try:
            account = pwd.getpwnam(user)
        except KeyError:
            results.append(
                Result(user, "ERROR", "account", None, None, "gleichnamiger Systembenutzer fehlt")
            )
            continue
        if Path(account.pw_dir) != user_path:
            results.append(
                Result(
                    user,
                    "ERROR",
                    "account",
                    None,
                    None,
                    f"Home des Systembenutzers ist {account.pw_dir}, erwartet wird {user_path}",
                )
            )
            continue
        try:
            directory_uid = user_path.stat().st_uid
        except OSError as exc:
            results.append(Result(user, "ERROR", "account", None, None, str(exc)))
            continue
        if directory_uid != account.pw_uid:
            try:
                owner = pwd.getpwuid(directory_uid).pw_name
            except KeyError:
                owner = f"UID {directory_uid}"
            results.append(
                Result(
                    user,
                    "ERROR",
                    "account",
                    None,
                    None,
                    f"Home-Ordner gehoert {owner}, erwartet wird {user} (UID {account.pw_uid})",
                )
            )
            continue
        user_max_age = float(age_overrides.get(user, max_age))
        candidates: list[tuple[float, str, Path]] = []
        timestamp_folders: list[tuple[float, str, Path, str | None]] = []
        timestamp_folder_seen = False
        mirrors: list[Path] = []
        marker_required = any(fnmatch.fnmatchcase(user, pattern) for pattern in marker_users)

        try:
            children = list(user_path.iterdir())
        except OSError as exc:
            results.append(Result(user, "STALE", "unreadable", None, None, str(exc)))
            continue

        for child in children:
            relative = f"{user}/{child.name}"
            if ignored(relative, ignore_patterns) or not child.is_dir():
                continue
            parsed = parse_backup_timestamp(child.name, formats)
            if parsed is not None:
                timestamp_folder_seen = True
                marker_error: str | None = None
                if marker_required:
                    marker = child / marker_name
                    try:
                        marker_payload = json.loads(marker.read_text(encoding="utf-8"))
                        if marker_payload.get("status") != "ok":
                            marker_error = f"{marker_name}: status ist nicht ok"
                        elif marker_payload.get("run_id") != child.name:
                            marker_error = f"{marker_name}: run_id stimmt nicht mit Ordnername ueberein"
                    except FileNotFoundError:
                        marker_error = f"{marker_name} fehlt"
                    except (OSError, UnicodeError, json.JSONDecodeError, AttributeError) as exc:
                        marker_error = f"{marker_name} ist ungueltig: {exc}"
                timestamp_folders.append((parsed.timestamp(), child.name, child, marker_error))
                if (not require_nonempty or folder_has_content(child)) and marker_error is None:
                    candidates.append((parsed.timestamp(), child.name, child))
                continue
            if any(fnmatch.fnmatchcase(child.name, pattern) for pattern in mirror_names):
                mirrors.append(child)

        mode = "timestamped" if timestamp_folder_seen else "mirror" if mirrors else "none"
        detail = ""
        latest_timestamp: float | None = None
        latest_path: Path | None = None
        previous_path: Path | None = None
        incomplete_error = False

        if mode == "timestamped":
            if candidates:
                ordered = sorted(candidates, key=lambda item: item[0], reverse=True)
                latest_timestamp, folder, latest_path = ordered[0]
                if len(ordered) > 1:
                    previous_path = ordered[1][2]
                detail = f"neuester nicht-leerer Ordner: {folder}"
                if marker_required:
                    detail += f"; gueltiger Erfolgsmarker {marker_name}"
            else:
                detail = "kein vollstaendiger Zeitstempel-Ordner gefunden"
        elif mode == "mirror":
            mirror_mtime = max((path.stat().st_mtime for path in mirrors), default=0.0)
            login_time = ssh_latest.get(user, 0.0)
            latest_timestamp = max(mirror_mtime, login_time) or None
            sources = []
            if login_time:
                sources.append(f"letzte SSH-Aktivitaet {iso(login_time)}")
            if mirror_mtime:
                sources.append(f"Ordner-mtime {iso(mirror_mtime)}")
            detail = ", ".join(sources) or "keine Aktivitaet gefunden"
        else:
            detail = "kein Zeitstempel- oder Spiegelordner gefunden"

        if marker_required and timestamp_folders:
            newest_time, newest_name, _, newest_marker_error = max(timestamp_folders, key=lambda item: item[0])
            incomplete_age = (now.timestamp() - newest_time) / 3600
            if newest_marker_error and incomplete_age > incomplete_grace_hours:
                incomplete_error = True
                detail += (
                    f"; neuester Lauf {newest_name} nach {incomplete_age:.2f} h unvollstaendig: "
                    f"{newest_marker_error}"
                )

        age = (now.timestamp() - latest_timestamp) / 3600 if latest_timestamp else None
        is_fresh = latest_timestamp is not None and age <= user_max_age
        volume_error = False
        volume_bytes: int | None = None
        previous_volume_bytes: int | None = None
        volume_delta_bytes: int | None = None
        if age is not None and age < -1:
            is_fresh = False
            detail += "; Zeitstempel liegt in der Zukunft"

        if check_volume and mode == "timestamped" and latest_path is not None:
            try:
                volume_bytes = measure_snapshot_volume_bytes(latest_path, volume_timeout)
                if previous_path is not None:
                    previous_volume_bytes = measure_snapshot_volume_bytes(previous_path, volume_timeout)
                    volume_delta_bytes = volume_bytes - previous_volume_bytes
                    detail += (
                        f"; Volumen {format_size(volume_bytes)}, vorher {format_size(previous_volume_bytes)}, "
                        f"Differenz {format_size(volume_delta_bytes, signed=True)}"
                    )
                    if volume_delta_bytes == 0:
                        volume_error = True
                        detail += "; Backup-Volumen ist unveraendert"
                else:
                    detail += f"; Volumen {format_size(volume_bytes)}, kein vorheriges Backup zum Vergleich"
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                volume_error = True
                detail += f"; Volumenmessung fehlgeschlagen: {exc}"
        elif check_volume and mode == "mirror" and mirrors:
            try:
                volume_bytes = sum(measure_volume_bytes(path, volume_timeout) for path in mirrors)
                old_result = previous_users.get(user, {}).get("result", {})
                old_latest = old_result.get("latest")
                old_volume = old_result.get("volume_bytes")
                current_latest = iso(latest_timestamp) if latest_timestamp else None
                if old_latest == current_latest:
                    previous_volume_bytes = old_result.get("previous_volume_bytes")
                    volume_delta_bytes = old_result.get("volume_delta_bytes")
                elif old_volume is not None:
                    previous_volume_bytes = int(old_volume)
                    volume_delta_bytes = volume_bytes - previous_volume_bytes
                if previous_volume_bytes is None:
                    detail += f"; Volumen {format_size(volume_bytes)}, noch keine vorherige Messung"
                else:
                    detail += (
                        f"; Volumen {format_size(volume_bytes)}, vorher {format_size(previous_volume_bytes)}, "
                        f"Differenz {format_size(int(volume_delta_bytes), signed=True)}"
                    )
                    if volume_delta_bytes == 0:
                        volume_error = True
                        detail += "; Backup-Volumen ist unveraendert"
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                volume_error = True
                detail += f"; Volumenmessung fehlgeschlagen: {exc}"

        result_status = "ERROR" if volume_error or incomplete_error else "OK" if is_fresh else "STALE"
        results.append(
            Result(
                user=user,
                status=result_status,
                mode=mode,
                latest=iso(latest_timestamp) if latest_timestamp else None,
                age_hours=round(age, 2) if age is not None else None,
                detail=detail,
                volume_bytes=volume_bytes,
                previous_volume_bytes=previous_volume_bytes,
                volume_delta_bytes=volume_delta_bytes,
            )
        )
    return results


def load_state(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"users": {}}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def smtp_recipients(cfg: dict[str, Any]) -> list[str]:
    value = cfg["smtp"].get("to", [])
    if isinstance(value, str):
        value = [value]
    return [str(item).strip() for item in value if str(item).strip()]


def send_mail(cfg: dict[str, Any], subject: str, body: str, html_body: str | None = None) -> None:
    smtp = cfg["smtp"]
    recipients = smtp_recipients(cfg)
    if not recipients:
        raise ValueError("smtp.to enthaelt keine Empfaengeradresse")

    message = EmailMessage()
    message["From"] = str(smtp["from_address"])
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(body)
    if html_body:
        message.add_alternative(html_body, subtype="html")

    timeout = float(smtp.get("timeout_seconds", 20))
    with smtplib.SMTP(str(smtp["host"]), int(smtp["port"]), timeout=timeout) as client:
        client.ehlo()
        username = str(smtp.get("username", ""))
        if username:
            client.login(username, str(smtp.get("password", "")))
        client.send_message(message, to_addrs=recipients)


def check_smtp(cfg: dict[str, Any]) -> str:
    smtp = cfg["smtp"]
    timeout = float(smtp.get("timeout_seconds", 20))
    with smtplib.SMTP(str(smtp["host"]), int(smtp["port"]), timeout=timeout) as client:
        client.ehlo()
        username = str(smtp.get("username", ""))
        if username:
            client.login(username, str(smtp.get("password", "")))
    return "SMTP-Verbindung und Anmeldung erfolgreich (Transport: plain, STARTTLS: nein)"


def format_results(title: str, results: list[Result]) -> str:
    lines = [title, "", f"Server: {socket.getfqdn()}", f"Zeit:   {local_now().isoformat(timespec='seconds')}", ""]
    for result in results:
        age = "unbekannt" if result.age_hours is None else f"{result.age_hours:.2f} h"
        volume = "unbekannt" if result.volume_bytes is None else format_size(result.volume_bytes)
        previous = "unbekannt" if result.previous_volume_bytes is None else format_size(result.previous_volume_bytes)
        delta = "unbekannt" if result.volume_delta_bytes is None else format_size(result.volume_delta_bytes, signed=True)
        lines.extend(
            [
                f"[{result.status}] {result.user}",
                f"  Typ: {result.mode}; Alter: {age}; Letztes Signal: {result.latest or '-'}",
                f"  Volumen: {volume}; Vorher: {previous}; Differenz: {delta}",
                f"  {result.detail}",
            ]
        )
    lines.extend(["", f"Konfiguration: {CONFIG_DISPLAY}", f"Status: {STATUS_DISPLAY}"])
    return "\n".join(lines)


def format_results_html(title: str, results: list[Result]) -> str:
    rows = []
    for result in results:
        age = "unbekannt" if result.age_hours is None else f"{result.age_hours:.2f} h"
        volume = "-" if result.volume_bytes is None else format_size(result.volume_bytes)
        previous = "-" if result.previous_volume_bytes is None else format_size(result.previous_volume_bytes)
        delta = "-" if result.volume_delta_bytes is None else format_size(result.volume_delta_bytes, signed=True)
        color = "#137333" if result.status == "OK" else "#b3261e"
        background = "#e6f4ea" if result.status == "OK" else "#fce8e6"
        rows.append(
            "<tr>"
            f'<td style="padding:10px;border-bottom:1px solid #ddd;">{html.escape(result.user)}</td>'
            f'<td style="padding:10px;border-bottom:1px solid #ddd;background:{background};color:{color};font-weight:700;">{html.escape(result.status)}</td>'
            f'<td style="padding:10px;border-bottom:1px solid #ddd;">{html.escape(result.mode)}</td>'
            f'<td style="padding:10px;border-bottom:1px solid #ddd;white-space:nowrap;">{html.escape(age)}</td>'
            f'<td style="padding:10px;border-bottom:1px solid #ddd;white-space:nowrap;">{html.escape(volume)}</td>'
            f'<td style="padding:10px;border-bottom:1px solid #ddd;white-space:nowrap;">{html.escape(previous)}</td>'
            f'<td style="padding:10px;border-bottom:1px solid #ddd;white-space:nowrap;">{html.escape(delta)}</td>'
            f'<td style="padding:10px;border-bottom:1px solid #ddd;">{html.escape(result.latest or "-")}</td>'
            f'<td style="padding:10px;border-bottom:1px solid #ddd;">{html.escape(result.detail)}</td>'
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><title>{html.escape(title)}</title></head>
<body style="margin:0;background:#f5f7f9;color:#202124;font-family:Arial,sans-serif;">
  <div style="max-width:1100px;margin:24px auto;background:#fff;border:1px solid #dfe3e7;border-radius:8px;overflow:hidden;">
    <div style="background:#263746;color:#fff;padding:20px 24px;">
      <h1 style="font-size:22px;margin:0;">{html.escape(title)}</h1>
      <p style="margin:8px 0 0;color:#d9e2e8;">Server: {html.escape(socket.getfqdn())} &middot; {html.escape(local_now().isoformat(timespec="seconds"))}</p>
    </div>
    <div style="padding:20px 24px;overflow-x:auto;">
      <table role="presentation" style="width:100%;border-collapse:collapse;font-size:14px;">
        <thead><tr style="text-align:left;background:#eef2f5;">
          <th style="padding:10px;">Benutzer</th><th style="padding:10px;">Status</th>
          <th style="padding:10px;">Typ</th><th style="padding:10px;">Alter</th>
          <th style="padding:10px;">Volumen</th><th style="padding:10px;">Vorher</th><th style="padding:10px;">Differenz</th>
          <th style="padding:10px;">Letztes Signal</th><th style="padding:10px;">Details</th>
        </tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
      <p style="margin:20px 0 0;color:#5f6368;font-size:12px;">Konfiguration: {html.escape(CONFIG_DISPLAY)} &middot; Status: {html.escape(STATUS_DISPLAY)}</p>
    </div>
  </div>
</body>
</html>"""


def main() -> int:
    global CONFIG_DISPLAY
    args = parse_args()
    CONFIG_DISPLAY = args.config
    try:
        cfg = load_config(args.config, args.smtp_json_file, args.schedule_json_file)
        alerts = cfg["alerts"]
        smtp_enabled = bool(cfg["smtp"].get("enabled", True))
        hostname = socket.gethostname()
        if args.check_smtp:
            print(check_smtp(cfg))
            return 0
        if args.send_test:
            if not smtp_enabled:
                raise ValueError("SMTP-Versand ist mit smtp.enabled = false deaktiviert")
            send_mail(
                cfg,
                f"[Backup-Check] SMTP-Test von {hostname}",
                f"SMTP-Test erfolgreich ausgeloest am {local_now().isoformat(timespec='seconds')}.\n",
                f"""<!doctype html><html lang="de"><body style="font-family:Arial,sans-serif;background:#f5f7f9;padding:24px;">
<div style="max-width:640px;margin:auto;background:#fff;border:1px solid #dfe3e7;border-radius:8px;padding:24px;">
<h1 style="font-size:22px;color:#137333;">SMTP-Test erfolgreich</h1>
<p>Der HTML-Mailversand von <strong>{html.escape(hostname)}</strong> funktioniert.</p>
<p style="color:#5f6368;">{html.escape(local_now().isoformat(timespec='seconds'))}</p>
</div></body></html>""",
            )
            print("SMTP-Testmail wurde versendet")
            return 0

        state_path = Path(str(alerts.get("state_file", "/var/lib/backup-check/state.json")))
        state = load_state(state_path)
        results = evaluate(cfg, state)
        try:
            storage_result = storage_check(cfg)
            if storage_result:
                results.append(storage_result)
        except Exception as exc:
            results.append(Result("BACKUP_TARGET_STORAGE", "ERROR", "storage", None, None, str(exc)))
        try:
            cleanup_result = cleanup_backups(cfg, dry_run=args.dry_run)
            if cleanup_result:
                results.append(cleanup_result)
        except Exception as exc:
            results.append(Result("BACKUP_TARGET_CLEANUP", "ERROR", "cleanup", None, None, str(exc)))
        if not results:
            raise RuntimeError("keine passenden Backup-Benutzer gefunden")
        stale = [result for result in results if result.status != "OK"]
        if args.verbose or args.dry_run:
            print(format_results("Backup-Pruefergebnis", results))

        old_users = state.setdefault("users", {})
        now_epoch = local_now().timestamp()
        reminder_seconds = float(alerts.get("reminder_hours", 24)) * 3600
        notify_stale: list[Result] = []
        recovered: list[Result] = []

        for result in results:
            old = old_users.get(result.user, {})
            if result.status != "OK":
                last_notice = float(old.get("last_notice", 0))
                if old.get("status") != result.status or now_epoch - last_notice >= reminder_seconds:
                    notify_stale.append(result)
            elif old.get("status") not in (None, "OK"):
                recovered.append(result)

        mail_sent = False
        if args.force and not args.dry_run:
            if not smtp_enabled:
                raise ValueError("Erzwungener Bericht nicht moeglich: SMTP ist deaktiviert")
            forced_label = "PROBLEME" if stale else "OK"
            send_mail(
                cfg,
                f"[Backup-{forced_label}] Erzwungener Check auf {hostname}",
                format_results("Manuell erzwungener Backup-Check", results),
                format_results_html("Manuell erzwungener Backup-Check", results),
            )
            mail_sent = True
            for result in stale:
                old_users.setdefault(result.user, {})["last_notice"] = now_epoch
        elif notify_stale and not args.dry_run and smtp_enabled:
            send_mail(
                cfg,
                f"[Backup-ALARM] {len(stale)} fehlerhafte Backups auf {hostname}",
                format_results("Folgende Backup-Pruefungen sind fehlgeschlagen:", stale),
                format_results_html("Backup-Alarm", stale),
            )
            mail_sent = True
            for result in notify_stale:
                old_users.setdefault(result.user, {})["last_notice"] = now_epoch

        if (
            not args.force
            and recovered
            and bool(alerts.get("send_recovery", True))
            and not args.dry_run
            and smtp_enabled
        ):
            send_mail(
                cfg,
                f"[Backup-OK] {len(recovered)} Backups wieder aktuell auf {hostname}",
                format_results("Folgende Backups sind wieder aktuell:", recovered),
                format_results_html("Backups wieder aktuell", recovered),
            )
            mail_sent = True

        if not args.dry_run:
            current_users = {result.user for result in results}
            for user in list(old_users):
                if user not in current_users:
                    del old_users[user]
            for result in results:
                entry = old_users.setdefault(result.user, {})
                entry["status"] = result.status
                entry["checked_at"] = now_epoch
                entry["result"] = asdict(result)
            save_state(state_path, state)

        summary = f"check complete: {len(results)} checks, {len(stale)} problems"
        if mail_sent:
            summary += ", notification sent"
        elif (notify_stale or recovered) and not smtp_enabled:
            summary += ", notification suppressed (SMTP disabled)"
        print(summary)
        return 1 if stale else 0
    except Exception as exc:
        print(f"backup-check error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
