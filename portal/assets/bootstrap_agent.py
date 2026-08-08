import base64
import json
import os
import pathlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import urllib.request


def fail(message):
    raise SystemExit(f"Onboarding fehlgeschlagen: {message}")


def command_exists(command):
    return subprocess.run(
        ["/bin/sh", "-c", f"command -v {command} >/dev/null 2>&1"],
        check=False,
    ).returncode == 0


def os_release():
    values = {}
    path = pathlib.Path("/etc/os-release")
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"').strip("'")
    return values


def ensure_backup_dependencies():
    release = os_release()
    distro_id = release.get("ID", "").lower()
    distro_like = release.get("ID_LIKE", "").lower().split()
    if distro_id not in {"debian", "ubuntu"} and "debian" not in distro_like:
        fail(f"nicht unterstützte Distribution: {release.get('PRETTY_NAME', distro_id or 'unbekannt')}; erwartet Debian/Ubuntu")

    packages_by_command = {
        "python3": "python3",
        "ssh": "openssh-client",
        "ssh-keygen": "openssh-client",
        "bash": "bash",
        "rsync": "rsync",
        "zstd": "zstd",
        "tar": "tar",
        "du": "coreutils",
        "crontab": "cron",
    }
    missing_packages = {
        package for command, package in packages_by_command.items() if not command_exists(command)
    }
    if not pathlib.Path("/etc/ssl/certs/ca-certificates.crt").is_file():
        missing_packages.add("ca-certificates")
    system_python = pathlib.Path("/usr/bin/python3")
    if not system_python.is_file():
        missing_packages.update({"python3", "python3-tomli"})
        toml_available = False
    else:
        toml_available = subprocess.run(
            [str(system_python), "-c", "import tomllib"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
    if system_python.is_file() and not toml_available:
        missing_packages.add("python3-tomli")

    if missing_packages:
        if not pathlib.Path("/usr/bin/apt-get").is_file():
            fail("apt-get fehlt auf der Debian/Ubuntu-Quelle")
        package_list = sorted(missing_packages)
        print("Installiere fehlende Backup-Abhängigkeiten: " + ", ".join(package_list), flush=True)
        environment = os.environ.copy()
        environment["DEBIAN_FRONTEND"] = "noninteractive"
        environment["APT_LISTCHANGES_FRONTEND"] = "none"
        try:
            subprocess.run(
                ["/usr/bin/apt-get", "-o", "DPkg::Lock::Timeout=180", "-q", "update"],
                env=environment,
                check=True,
            )
            subprocess.run(
                ["/usr/bin/apt-get", "-o", "DPkg::Lock::Timeout=180", "-y", "--no-install-recommends", "install", *package_list],
                env=environment,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            fail(f"Paketinstallation fehlgeschlagen (apt-get Status {exc.returncode})")

    missing_commands = [command for command in packages_by_command if not command_exists(command)]
    toml_import = subprocess.run(
        ["/usr/bin/python3", "-c", "try:\n import tomllib\nexcept ModuleNotFoundError:\n import tomli"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if missing_commands or toml_import.returncode != 0:
        details = ", ".join(missing_commands) or "Python-TOML-Modul"
        fail("Abhängigkeitsprüfung nach Installation fehlgeschlagen: " + details)
    print("Backup-Abhängigkeiten geprüft: Debian/Ubuntu, bash, rsync, OpenSSH, tar und zstd sind bereit.", flush=True)


def ensure_ssh_identity(ssh_dir, client_slug):
    key_path = ssh_dir / f"raven_backup_{client_slug}"
    legacy_key_path = ssh_dir / f"pulseone_backup_{client_slug}"

    if key_path.is_symlink():
        fail(f"unsicherer privater SSH-Schlüssel: {key_path}")
    if not key_path.exists():
        if legacy_key_path.is_symlink():
            fail(f"unsicherer historischer SSH-Schlüssel: {legacy_key_path}")
        if legacy_key_path.exists():
            legacy_stat = legacy_key_path.lstat()
            if not stat.S_ISREG(legacy_stat.st_mode) or legacy_stat.st_uid != 0:
                fail(f"unsicherer historischer SSH-Schlüssel: {legacy_key_path}")
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{key_path.name}.", dir=ssh_dir
            )
            try:
                os.fchmod(file_descriptor, 0o600)
                with os.fdopen(file_descriptor, "wb") as target, legacy_key_path.open("rb") as source:
                    shutil.copyfileobj(source, target)
                os.replace(temporary_name, key_path)
            finally:
                try:
                    pathlib.Path(temporary_name).unlink()
                except FileNotFoundError:
                    pass
            print(
                f"Historische SSH-Identität {legacy_key_path.name} als {key_path.name} übernommen.",
                flush=True,
            )
        else:
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)],
                check=True,
            )

    key_stat = key_path.lstat()
    if key_path.is_symlink() or not stat.S_ISREG(key_stat.st_mode) or key_stat.st_uid != 0:
        fail(f"unsicherer privater SSH-Schlüssel: {key_path}")
    os.chmod(key_path, 0o600)
    derived = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(key_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    public_parts = derived.stdout.strip().split()
    if derived.returncode != 0 or len(public_parts) < 2 or public_parts[0] != "ssh-ed25519":
        fail(f"privater SSH-Schlüssel ist ungültig oder kein Ed25519-Schlüssel: {key_path}")
    public_key = " ".join(public_parts[:2])

    public_path = key_path.with_name(key_path.name + ".pub")
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{public_path.name}.", dir=ssh_dir
    )
    try:
        os.fchmod(file_descriptor, 0o644)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            handle.write(public_key + "\n")
        os.replace(temporary_name, public_path)
    finally:
        try:
            pathlib.Path(temporary_name).unlink()
        except FileNotFoundError:
            pass
    return key_path, public_key


if os.geteuid() != 0:
    fail("dieses Programm muss als root ausgefuehrt werden")

ensure_backup_dependencies()
if "--dependencies-only" in sys.argv:
    raise SystemExit(0)

ssh_dir = pathlib.Path("/root/.ssh")
ssh_dir.mkdir(mode=0o700, exist_ok=True)
key_path, public_key = ensure_ssh_identity(ssh_dir, CLIENT_SLUG)

payload = json.dumps(
    {
        "public_key": public_key,
        "source_hostname": socket.getfqdn(),
        "has_mariadb": bool(subprocess.run(["/bin/sh", "-c", "command -v mariadb >/dev/null && command -v mariadb-dump >/dev/null"]).returncode == 0),
    }
).encode("utf-8")
request = urllib.request.Request(
    PORTAL_URL + "/api/onboard/register",
    data=payload,
    method="POST",
    headers={"Authorization": f"Bearer {DEPLOYMENT_TOKEN}", "Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.loads(response.read().decode("utf-8"))
except Exception as exc:
    fail(f"Registrierung beim Portal nicht moeglich: {exc}")

backup_path = pathlib.Path("/root/backup")
backup_path.write_bytes(base64.b64decode(result["backup_script_b64"]))
os.chmod(backup_path, 0o700)
config_path = pathlib.Path("/root/backup-job.toml")
config_path.write_bytes(base64.b64decode(result["backup_config_b64"]))
os.chmod(config_path, 0o600)

config_file = ssh_dir / "config"
existing = config_file.read_text(encoding="utf-8") if config_file.exists() else ""
begin = f"# BEGIN RAVEN BACKUP {CLIENT_SLUG}"
end = f"# END RAVEN BACKUP {CLIENT_SLUG}"
block = begin + "\n" + result["ssh_config"].rstrip() + "\n" + end
for marker_name in ("RAVEN", "PULSEONE"):
    old_begin = f"# BEGIN {marker_name} BACKUP {CLIENT_SLUG}"
    old_end = f"# END {marker_name} BACKUP {CLIENT_SLUG}"
    pattern = re.compile(re.escape(old_begin) + r".*?" + re.escape(old_end), re.S)
    existing = pattern.sub("", existing).rstrip()
config_file.write_text((existing + "\n\n" + block + "\n").lstrip(), encoding="utf-8")
os.chmod(config_file, 0o600)

known_hosts = ssh_dir / "known_hosts"
known = known_hosts.read_text(encoding="utf-8") if known_hosts.exists() else ""
if result["known_hosts_line"] not in known.splitlines():
    with known_hosts.open("a", encoding="utf-8") as handle:
        handle.write(result["known_hosts_line"] + "\n")
os.chmod(known_hosts, 0o600)

cron = subprocess.run(["crontab", "-l"], text=True, capture_output=True)
cron_text = cron.stdout if cron.returncode == 0 else ""
cron_begin = f"# BEGIN RAVEN BACKUP {CLIENT_SLUG}"
cron_end = f"# END RAVEN BACKUP {CLIENT_SLUG}"
for marker_name in ("RAVEN", "PULSEONE"):
    old_begin = f"# BEGIN {marker_name} BACKUP {CLIENT_SLUG}"
    old_end = f"# END {marker_name} BACKUP {CLIENT_SLUG}"
    cron_pattern = re.compile(re.escape(old_begin) + r".*?" + re.escape(old_end) + r"\n?", re.S)
    cron_text = cron_pattern.sub("", cron_text).rstrip()
# Remove only historical versions of this exact backup job. Other root cron jobs
# remain untouched. This also avoids a duplicate schedule when onboarding an
# already managed source server.
cron_lines = []
for cron_line in cron_text.splitlines():
    if "/root/backup" in cron_line and "backup-job.toml" in cron_line:
        continue
    cron_lines.append(cron_line)
cron_text = "\n".join(cron_lines).rstrip()
cron_block = cron_begin + "\n" + result["cron_line"] + "\n" + cron_end
subprocess.run(["crontab", "-"], input=cron_text + "\n\n" + cron_block + "\n", text=True, check=True)

subprocess.run(["/usr/bin/python3", str(backup_path), "--config", str(config_path), "--preflight-only"], check=True)
subprocess.run(["/usr/bin/python3", str(backup_path), "--config", str(config_path), "--check-status"], check=True)
print("Onboarding, Preflight und Portal-Heartbeat erfolgreich.")
if result.get("run_initial_backup"):
    print("Initiales Backup wird gestartet ...")
    subprocess.run(["/usr/bin/python3", str(backup_path), "--config", str(config_path)], check=True)
    print("Initiales Backup erfolgreich.")
