"""The read-only explorer for backed-up files and archives."""

from __future__ import annotations

from collections import OrderedDict
import mimetypes
import os
import sqlite3
import stat as statlib
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from starlette.background import BackgroundTask

from core import HOME_ROOT, LOG, db, format_size
from auth import audit, require_user
from rendering import render


router = APIRouter()


ARCHIVE_SCAN_LOCK = threading.BoundedSemaphore(2)
ARCHIVE_CACHE_LOCK = threading.Lock()
ARCHIVE_CACHE: OrderedDict[tuple[str, int, int], tuple[float, list[str], bool]] = OrderedDict()

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


@router.get("/explorer", response_class=HTMLResponse)
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


@router.get("/clients/{client_id}/explorer", response_class=HTMLResponse)
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


@router.get("/clients/{client_id}/explorer/download")
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


@router.get("/clients/{client_id}/explorer/archive", response_class=HTMLResponse)
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


@router.get("/clients/{client_id}/explorer/archive/download")
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
