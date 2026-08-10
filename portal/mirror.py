#!/usr/bin/env python3
"""Replication of the whole backup store to remote mirror servers.

The portal keeps the credentials and the schedule; this module owns everything
that turns those settings into commands. It is deliberately free of database
and web dependencies so the command construction can be tested on its own.

The rsync options are operator supplied, so they pass an allowlist first. rsync
can execute arbitrary programs through options such as ``-e`` or
``--rsync-path``; only flags that describe *what* is transferred are accepted,
never ones that describe *how* the remote side is reached.
"""

from __future__ import annotations

import re
import shlex
from typing import Any


DEFAULT_RSYNC_OPTIONS = "-a --delete --stats"

# Keeps run directories that the source has already rotated away, so the mirror
# can hold a longer history than the target server itself. Pair it with a
# retention on the mirror, otherwise the copy grows without a bound.
HISTORY_RSYNC_OPTIONS = "-a --delete --stats --filter='P backup_*/[0-9]*'"
MAX_RSYNC_OPTIONS = 40

# Short flags that only affect the transfer itself.
SAFE_SHORT_FLAGS = set("avzhHAXPS")

SAFE_LONG_FLAGS = {
    "--archive", "--verbose", "--compress", "--human-readable", "--hard-links",
    "--acls", "--xattrs", "--partial", "--progress", "--stats", "--itemize-changes",
    "--delete", "--delete-before", "--delete-during", "--delete-delay", "--delete-after",
    "--delete-excluded", "--prune-empty-dirs", "--numeric-ids", "--sparse", "--inplace",
    "--whole-file", "--no-whole-file", "--checksum", "--one-file-system", "--quiet",
    "--ignore-existing", "--size-only", "--omit-dir-times", "--links", "--perms",
    "--times", "--group", "--owner", "--devices", "--specials", "--recursive",
}

# Filter rules that only decide which files take part. "merge" and "dir-merge"
# would read a rule file from disk, so they stay out.
SAFE_FILTER_RULE = re.compile(
    r"^--filter=(P|protect|H|hide|S|show|R|risk|\+|include|-|exclude) [^\s`$;&|<>()]{1,200}$"
)

SAFE_VALUE_FLAGS = (
    re.compile(r"^--bwlimit=\d{1,9}[KMG]?$"),
    re.compile(r"^--compress-level=\d$"),
    re.compile(r"^--timeout=\d{1,6}$"),
    re.compile(r"^--contimeout=\d{1,6}$"),
    re.compile(r"^--max-delete=\d{1,9}$"),
    re.compile(r"^--exclude=[^\s`$;&|<>()]{1,200}$"),
    re.compile(r"^--include=[^\s`$;&|<>()]{1,200}$"),
    re.compile(r"^--partial-dir=[A-Za-z0-9._/-]{1,100}$"),
)

# Options that hand rsync a command to run or a path to reach the peer.
FORBIDDEN_FLAGS = {
    "-e", "--rsh", "--rsync-path", "-M", "--remote-option", "--files-from",
    "--daemon", "--config", "--log-file", "--log-file-format", "--out-format",
    "--password-file", "--copy-dest", "--link-dest", "--compare-dest", "--temp-dir",
}

HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$")
USERNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
ABSOLUTE_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9._/-]{0,200}$")
RUN_DIRECTORY_PATTERN = r".*/backup_[^/]+/[0-9]{8,20}"


def validated_rsync_options(raw: str) -> list[str]:
    """Return the operator's rsync options, rejecting anything that could run code."""
    try:
        tokens = shlex.split(raw.strip())
    except ValueError as exc:
        raise ValueError(f"rsync-Optionen sind nicht lesbar: {exc}") from exc
    if len(tokens) > MAX_RSYNC_OPTIONS:
        raise ValueError(f"Hoechstens {MAX_RSYNC_OPTIONS} rsync-Optionen sind erlaubt")
    for token in tokens:
        base = token.split("=", 1)[0]
        if token in FORBIDDEN_FLAGS or base in FORBIDDEN_FLAGS:
            raise ValueError(f"Option {token} ist nicht erlaubt, weil sie fremde Befehle ausfuehren kann")
        if not token.startswith("-"):
            raise ValueError(f"{token} ist keine Option; Quelle und Ziel setzt RAVEN selbst")
        if token in SAFE_LONG_FLAGS:
            continue
        if any(pattern.fullmatch(token) for pattern in SAFE_VALUE_FLAGS):
            continue
        if SAFE_FILTER_RULE.fullmatch(token):
            continue
        if not token.startswith("--") and len(token) > 1 and set(token[1:]) <= SAFE_SHORT_FLAGS:
            continue
        raise ValueError(f"Option {token} steht nicht auf der Freigabeliste")
    return tokens


def ssh_transport(key_path: str, known_hosts_path: str, port: int) -> list[str]:
    """Return the ssh command rsync should use for the mirror connection."""
    return [
        "/usr/bin/ssh",
        "-p", str(int(port)),
        "-i", key_path,
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts_path}",
        "-o", "ConnectTimeout=20",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=10",
    ]


ACCOUNT_PREFIX_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]{0,15}$")

MAX_INTERVAL_HOURS = 720
INTERVAL_UNITS = ("hours", "days")


def interval_from_unit(value: Any, unit: str) -> int:
    """Turn the operator's number and unit into hours."""
    if unit not in INTERVAL_UNITS:
        raise ValueError("Einheit des Intervalls ist unbekannt")
    amount = int(value)
    hours = amount * 24 if unit == "days" else amount
    if not 1 <= hours <= MAX_INTERVAL_HOURS:
        limit = MAX_INTERVAL_HOURS // 24 if unit == "days" else MAX_INTERVAL_HOURS
        raise ValueError(
            f"Intervall muss zwischen 1 und {limit} {'Tagen' if unit == 'days' else 'Stunden'} liegen"
        )
    return hours


def interval_fields(hours: int) -> tuple[int, str]:
    """Return the number and unit that show an interval most naturally."""
    hours = int(hours)
    if hours >= 24 and hours % 24 == 0:
        return hours // 24, "days"
    return hours, "hours"


def describe_interval(hours: int) -> str:
    amount, unit = interval_fields(hours)
    if unit == "days":
        return "täglich" if amount == 1 else f"alle {amount} Tage"
    return "stündlich" if amount == 1 else f"alle {amount} Stunden"


def scope_filters(account_prefix: str) -> list[str]:
    """Restrict the transfer to the target accounts of the backup system.

    The home root also holds directories that have nothing to do with RAVEN.
    Both rules are anchored to the transfer root and carry no ``**``, so they
    decide only which top level entries take part and leave every rule about
    the content inside an account to the operator.
    """
    if not ACCOUNT_PREFIX_PATTERN.fullmatch(account_prefix):
        raise ValueError("Benutzerpraefix ist fuer die Auswahl der Ordner ungueltig")
    return [f"--filter=+ /{account_prefix}*/", "--filter=- /*"]


def remote_destination(username: str, host: str, remote_path: str) -> str:
    return f"{username}@{host}:{remote_path.rstrip('/')}/"


def rsync_command(
    *,
    source_path: str,
    username: str,
    host: str,
    remote_path: str,
    options: list[str],
    key_path: str,
    known_hosts_path: str,
    port: int,
    account_prefix: str,
) -> list[str]:
    """Build the replication command for one mirror target.

    The scope rules come after the operator's options so their own rules keep
    precedence for anything inside an account.
    """
    return [
        "/usr/bin/rsync",
        *options,
        *scope_filters(account_prefix),
        "-e", shlex.join(ssh_transport(key_path, known_hosts_path, port)),
        source_path.rstrip("/") + "/",
        remote_destination(username, host, remote_path),
    ]


def ssh_command(
    *, username: str, host: str, remote_command: str, key_path: str, known_hosts_path: str, port: int
) -> list[str]:
    return [*ssh_transport(key_path, known_hosts_path, port), f"{username}@{host}", remote_command]


def disk_usage_command(remote_path: str) -> str:
    """Return a remote command that reports total and free bytes of the target."""
    return f"df -P -B1 -- {shlex.quote(remote_path)}"


def parse_disk_usage(output: str) -> tuple[int, int]:
    """Return total and available bytes from ``df -P -B1`` output."""
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[1].isdigit() and parts[3].isdigit():
            return int(parts[1]), int(parts[3])
    raise ValueError("df lieferte keine auswertbare Zeile")


def parse_transferred_bytes(output: str) -> int | None:
    """Return the transferred byte count rsync reports with --stats."""
    match = re.search(r"Total transferred file size:\s*([\d.,]+)\s*bytes", output)
    if not match:
        match = re.search(r"sent\s+([\d.,]+)\s+bytes", output)
    if not match:
        return None
    try:
        return int(match.group(1).replace(".", "").replace(",", ""))
    except ValueError:
        return None


def foreign_entries_command(remote_path: str, account_prefix: str) -> str:
    """Return a remote command listing entries that are not backup accounts."""
    if not ACCOUNT_PREFIX_PATTERN.fullmatch(account_prefix):
        raise ValueError("Benutzerpraefix ist ungueltig")
    if not ABSOLUTE_PATH_PATTERN.fullmatch(remote_path):
        raise ValueError("Zielpfad ist nicht sicher genug")
    base = shlex.quote(remote_path.rstrip("/"))
    return (
        f"find {base} -mindepth 1 -maxdepth 1 "
        f"! -name {shlex.quote(account_prefix + '*')} -printf '%f\n' 2>/dev/null | head -50"
    )


def retention_command(remote_path: str, retention_days: int) -> str:
    """Return a remote command that removes run directories beyond the retention.

    Only directories that look exactly like a backup run of one target account
    are considered, so nothing else on the mirror can be touched.
    """
    if retention_days < 1:
        raise ValueError("Aufbewahrung muss mindestens einen Tag betragen")
    if not ABSOLUTE_PATH_PATTERN.fullmatch(remote_path):
        raise ValueError("Zielpfad ist fuer die Bereinigung nicht sicher genug")
    base = shlex.quote(remote_path.rstrip("/"))
    return (
        f"find {base} -mindepth 2 -maxdepth 2 -type d -regextype posix-extended "
        f"-regex {shlex.quote(RUN_DIRECTORY_PATTERN)} -mtime +{int(retention_days)} "
        "-print -exec rm -rf -- {} +"
    )


def validated_target(
    *, host: str, username: str, remote_path: str, ssh_port: Any, interval_hours: Any,
    retention_days: Any, rsync_options: str,
) -> dict[str, Any]:
    """Validate every operator supplied field of a mirror target."""
    host = host.strip().lower()
    username = username.strip()
    remote_path = remote_path.strip().rstrip("/") or "/"
    if not HOST_PATTERN.fullmatch(host):
        raise ValueError("Hostname ist ungueltig")
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Benutzername ist ungueltig")
    if not ABSOLUTE_PATH_PATTERN.fullmatch(remote_path) or remote_path == "/":
        raise ValueError("Zielpfad muss ein absoluter Pfad unterhalb von / sein")
    port = int(ssh_port)
    if not 1 <= port <= 65535:
        raise ValueError("SSH-Port ist ungueltig")
    interval = int(interval_hours)
    if not 1 <= interval <= MAX_INTERVAL_HOURS:
        raise ValueError(
            f"Replikationsintervall muss zwischen 1 und {MAX_INTERVAL_HOURS} Stunden liegen"
        )
    retention = int(retention_days)
    if not 0 <= retention <= 3650:
        raise ValueError("Aufbewahrung muss zwischen 0 und 3650 Tagen liegen")
    return {
        "host": host,
        "username": username,
        "remote_path": remote_path,
        "ssh_port": port,
        "interval_hours": interval,
        "retention_days": retention,
        "rsync_options": " ".join(validated_rsync_options(rsync_options or DEFAULT_RSYNC_OPTIONS)),
    }


def normalized_private_key(raw: str) -> str:
    """Return an OpenSSH private key, rejecting anything that is not one."""
    key = raw.replace("\r\n", "\n").strip()
    if not key.startswith("-----BEGIN ") or "PRIVATE KEY-----" not in key.split("\n", 1)[0]:
        raise ValueError("Es wird ein privater OpenSSH-Schluessel im PEM-Format erwartet")
    if not key.rstrip().endswith("-----"):
        raise ValueError("Der private Schluessel ist unvollstaendig")
    if len(key) > 16384:
        raise ValueError("Der private Schluessel ist zu gross")
    return key + "\n"


def normalized_host_key(raw: str, host: str, port: int) -> str:
    """Return the known_hosts lines for the target, restricted to its address."""
    lines: list[str] = []
    expected = f"[{host}]:{int(port)}" if int(port) != 22 else host
    for line in raw.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            raise ValueError("Hostschluessel-Eintrag ist unvollstaendig")
        if parts[0] != expected:
            parts[0] = expected
        lines.append(" ".join(parts[:3]))
    if not lines:
        raise ValueError("Es wurde kein Hostschluessel gefunden")
    return "\n".join(lines) + "\n"
