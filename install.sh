#!/usr/bin/env bash
# Fully automated installer for RAVEN.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly APP_NAME="backup-portal"
readonly APP_DIR="/opt/backup-portal"
readonly CONFIG_DIR="/etc/backup-portal"
readonly CONFIG_FILE="${CONFIG_DIR}/config.toml"
readonly CHECKER_CONFIG_FILE="${CONFIG_DIR}/backup-check.toml"
readonly DATA_DIR="/var/lib/backup-portal"
readonly CHECKER_DATA_DIR="/var/lib/backup-check"
readonly SERVICE_FILE="/etc/systemd/system/backup-portal.service"
readonly CERT_RENEW_SERVICE_FILE="/etc/systemd/system/backup-portal-cert-renew.service"
readonly CERT_RENEW_TIMER_FILE="/etc/systemd/system/backup-portal-cert-renew.timer"
readonly SSH_DROPIN="/etc/ssh/sshd_config.d/90-backup-portal-port.conf"
readonly CERTBOT_HOOK="/etc/letsencrypt/renewal-hooks/deploy/restart-backup-portal"
readonly ACME_STATE_DIR="/var/lib/backup-portal/acme"
readonly CLOUDFLARE_CREDENTIALS_FILE="/etc/backup-portal/cloudflare-acme.toml"

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INTERACTIVE=1
TEMP_DIR=""
SERVICE_WAS_ACTIVE=0

log() { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf 'WARNUNG: %s\n' "$*" >&2; }
die() { printf 'FEHLER: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Verwendung: sudo ./install.sh [--non-interactive]

Ohne Optionen fuehrt das Skript durch die gesamte Installation. Im
nicht-interaktiven Modus werden Werte aus Umgebungsvariablen gelesen.
Mindestens erforderlich sind dann:

  DOMAIN_TLD, ADMIN_PASSWORD, SMTP_PASSWORD

Wichtige optionale Variablen:

  DOMAIN_TLD                  DNS-Basisdomain/Cloudflare-Zone, z. B. example.com
  DOMAIN_SUBDOMAIN            optionale Subdomain, z. B. backup
  PORTAL_PORT                 Standard: 49180
  BACKUP_SSH_PORT             Standard: 49150
  BACKUP_TARGET_HOSTNAME      Standard: Ausgabe von hostname
  ADMIN_USERNAME              Standard: admin
  TLS_MODE                    letsencrypt-dns-cloudflare, letsencrypt-dns-manual,
                              letsencrypt-http oder existing
  ACME_EMAIL                  erforderlich bei Let's Encrypt
  ACME_DNS_RESOLVERS          Standard: 1.1.1.1,8.8.8.8
  ACME_DNS_TIMEOUT_SECONDS    Standard: 7200
  ACME_DNS_POLL_SECONDS       Standard: 15
  ACME_FORCE_REISSUE          yes erzwingt DNS-Neuausstellung bei vorhandenem Zertifikat
  CLOUDFLARE_API_TOKEN        API-Token mit Zone DNS Edit
  CLOUDFLARE_ZONE_ID          optional; vermeidet Zone-Lookup
  TLS_CERT_PATH, TLS_KEY_PATH erforderlich bei existing
  SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_FROM, SMTP_TO
  CHECKER_INTERVAL_MINUTES, MINIMUM_FREE_PERCENT
  SNAPSHOT_RETENTION_DAYS, CLEANUP_RUN_HOUR
  IMPORT_EXISTING_CLIENTS     yes oder no

Das Admin-Passwort wird nur als scrypt-Hash in SQLite gespeichert. Passwoerter
werden nicht auf der Kommandozeile an Python-Prozesse uebergeben.
EOF
}

while (($#)); do
    case "$1" in
        --non-interactive) INTERACTIVE=0 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unbekannte Option: $1" ;;
    esac
    shift
done

cleanup() {
    if [[ -n "${TEMP_DIR}" && -d "${TEMP_DIR}" ]]; then
        rm -f -- "${TEMP_DIR}/portal.toml" "${TEMP_DIR}/checker.toml" "${TEMP_DIR}/ssh-port.conf" "${TEMP_DIR}/cloudflare-acme.toml" "${TEMP_DIR}/cloudflare-check.toml"
        rmdir -- "${TEMP_DIR}" 2>/dev/null || true
    fi
}

on_error() {
    local exit_code=$?
    local line=${1:-unknown}
    printf '\nFEHLER: Installation in Zeile %s abgebrochen (Status %s).\n' "$line" "$exit_code" >&2
    if ((SERVICE_WAS_ACTIVE)) && ! systemctl is-active --quiet "${APP_NAME}.service" 2>/dev/null; then
        warn "Der vorher aktive Portal-Dienst ist gestoppt; Startversuch wird ausgefuehrt."
        systemctl start "${APP_NAME}.service" 2>/dev/null || true
    fi
    exit "$exit_code"
}

trap cleanup EXIT
trap 'on_error $LINENO' ERR

require_root() {
    ((EUID == 0)) || die "Dieses Skript muss als root ausgefuehrt werden (sudo ./install.sh)."
}

require_supported_os() {
    [[ -r /etc/os-release ]] || die "/etc/os-release fehlt. Unterstuetzt werden Debian und Ubuntu."
    # shellcheck disable=SC1091
    . /etc/os-release
    local family=" ${ID:-} ${ID_LIKE:-} "
    if [[ "$family" != *" debian "* && "$family" != *" ubuntu "* ]]; then
        die "Nicht unterstuetztes Betriebssystem: ${PRETTY_NAME:-unbekannt}. Erwartet wird Debian/Ubuntu."
    fi
    info "Betriebssystem: ${PRETTY_NAME:-${ID}}"
}

require_project_files() {
    local required=(
        "portal/app.py"
        "portal/run.py"
        "portal/requirements.txt"
        "portal/backup-portal.service"
        "portal/certbot-deploy-hook.sh"
        "portal/acme_dns_hook.py"
        "portal/acme_manager.py"
        "portal/domain_config.py"
        "portal/runtime_config.py"
        "portal/backup_schedule.py"
        "portal/mirror.py"
        "portal/backup-portal-cert-renew.service"
        "portal/backup-portal-cert-renew.timer"
        "portal/README.md"
        "portal/assets/bootstrap_agent.py"
        "backupscript/backup_job.py"
        "backup_check.py"
    )
    local relative
    for relative in "${required[@]}"; do
        [[ -f "${PROJECT_ROOT}/${relative}" ]] || die "Projektdatei fehlt: ${relative}"
    done
}

install_dependencies() {
    log "Systemabhaengigkeiten installieren und pruefen"
    export DEBIAN_FRONTEND=noninteractive
    /usr/bin/apt-get -o DPkg::Lock::Timeout=180 -q update
    /usr/bin/apt-get -o DPkg::Lock::Timeout=180 -y --no-install-recommends install \
        ca-certificates certbot curl dnsutils iproute2 openssh-server openssl rsync tar ufw zstd \
        python3 python3-pip python3-venv build-essential cargo libffi-dev libssl-dev pkg-config

    local command
    for command in python3 curl dig ssh sshd rsync tar zstd certbot openssl systemctl; do
        command -v "$command" >/dev/null 2>&1 || die "Abhaengigkeit fehlt nach der Installation: ${command}"
    done
    python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit(f"Python 3.10 oder neuer erforderlich, gefunden: {sys.version.split()[0]}")
print(f"    Python: {sys.version.split()[0]}")
PY
    if ! python3 -c 'import tomllib' >/dev/null 2>&1 && ! python3 -c 'import tomli' >/dev/null 2>&1; then
        /usr/bin/apt-get -o DPkg::Lock::Timeout=180 -y --no-install-recommends install python3-tomli
    fi
}

config_value() {
    local file=$1 section=$2 key=$3 fallback=$4
    local parser="python3"
    if ! python3 -c 'import tomllib' >/dev/null 2>&1 && [[ -x "$APP_DIR/venv/bin/python" ]]; then
        parser="$APP_DIR/venv/bin/python"
    fi
    "$parser" - "$file" "$section" "$key" "$fallback" <<'PY'
import sys
from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        print(sys.argv[4])
        raise SystemExit

path, section, key, fallback = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
try:
    with path.open("rb") as handle:
        value = tomllib.load(handle)
    for part in section.split("."):
        value = value[part]
    value = value[key]
    if isinstance(value, list):
        print(",".join(str(item) for item in value))
    elif isinstance(value, bool):
        print("yes" if value else "no")
    else:
        print(value)
except Exception:
    print(fallback)
PY
}

cloudflare_token_value() {
    local file=$1
    python3 - "$file" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    if path.suffix.lower() == ".toml":
        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib
        with path.open("rb") as handle:
            print(tomllib.load(handle).get("cloudflare", {}).get("api_token", ""))
    else:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            if "=" not in raw_line:
                continue
            key, value = raw_line.split("=", 1)
            if key.strip() == "dns_cloudflare_api_token":
                print(value.strip())
                break
        else:
            print("")
except Exception:
    print("")
PY
}

database_setting_value() {
    local config_file=$1 section=$2 key=$3 fallback=${4-} python_bin=python3
    [[ -x "$APP_DIR/venv/bin/python" ]] && python_bin="$APP_DIR/venv/bin/python"
    "$python_bin" - "$config_file" "$section" "$key" "$fallback" <<'PY'
import base64
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

config_path, section, key, fallback = sys.argv[1:]
try:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib
    with open(config_path, "rb") as handle:
        config = tomllib.load(handle)
    connection = sqlite3.connect(f"file:{Path(config['database']['path'])}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        if section == "smtp":
            if key == "to":
                try:
                    recipient = connection.execute(
                        "SELECT email FROM users WHERE active=1 AND receive_notifications=1 "
                        "AND TRIM(email)<>'' ORDER BY (role='admin') DESC,id LIMIT 1"
                    ).fetchone()
                except sqlite3.OperationalError:
                    legacy = connection.execute(
                        "SELECT recipients_json FROM smtp_settings WHERE id=1"
                    ).fetchone()
                    legacy_values = json.loads(legacy["recipients_json"] or "[]") if legacy else []
                    recipient = {"email": str(legacy_values[0]).strip()} if legacy_values else None
                print(recipient["email"] if recipient else fallback)
                raise SystemExit(0)
            row = connection.execute("SELECT * FROM smtp_settings WHERE id=1").fetchone()
            column = {"host": "host", "port": "port", "username": "username", "password": "password_ciphertext",
                      "from_address": "from_address"}[key]
        elif section == "cloudflare":
            row = connection.execute("SELECT * FROM acme_settings WHERE id=1").fetchone()
            column = {"api_token": "cloudflare_token_ciphertext", "zone_id": "cloudflare_zone_id",
                      "ttl": "cloudflare_ttl"}[key]
        else:
            raise KeyError(section)
    finally:
        connection.close()
    if not row:
        raise LookupError("setting missing")
    value = row[column]
    if key in {"password", "api_token"} and value:
        from cryptography.fernet import Fernet
        secret = str(config["security"]["session_secret"])
        cipher_key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
        value = Fernet(cipher_key).decrypt(str(value).encode("ascii")).decode("utf-8")
    print(value if value is not None else fallback)
except Exception:
    print(fallback)
PY
}

ask() {
    local variable=$1 label=$2
    local current=${!variable-} entered=""
    if ((INTERACTIVE)); then
        read -r -p "${label} [${current}]: " entered
        if [[ -n "$entered" ]]; then
            printf -v "$variable" '%s' "$entered"
        fi
    fi
}

ask_optional() {
    local variable=$1 label=$2
    local current=${!variable-} entered=""
    if ((INTERACTIVE)); then
        read -r -p "${label} [${current:-leer}; - setzt leer]: " entered
        if [[ "$entered" == "-" ]]; then
            printf -v "$variable" '%s' ""
        elif [[ -n "$entered" ]]; then
            printf -v "$variable" '%s' "$entered"
        fi
    fi
}

ask_yes_no() {
    local variable=$1 label=$2
    local current=${!variable-} entered=""
    if ((INTERACTIVE)); then
        while true; do
            read -r -p "${label} [${current}]: " entered
            entered=${entered:-$current}
            case "${entered,,}" in
                y|yes|j|ja) printf -v "$variable" '%s' "yes"; return ;;
                n|no|nein) printf -v "$variable" '%s' "no"; return ;;
                *) warn "Bitte yes oder no eingeben." ;;
            esac
        done
    fi
}

read_admin_password() {
    if ((INTERACTIVE)); then
        local first="" second=""
        while true; do
            read -r -s -p "Initiales Admin-Passwort (mindestens 12 Zeichen): " first
            printf '\n'
            read -r -s -p "Admin-Passwort wiederholen: " second
            printf '\n'
            if ((${#first} < 12)); then
                warn "Das Passwort ist kuerzer als 12 Zeichen."
            elif [[ "$first" != "$second" ]]; then
                warn "Die Passwoerter stimmen nicht ueberein."
            else
                ADMIN_PASSWORD=$first
                return
            fi
        done
    fi
    [[ ${#ADMIN_PASSWORD} -ge 12 ]] || die "ADMIN_PASSWORD muss im nicht-interaktiven Modus mindestens 12 Zeichen haben."
}

read_smtp_password() {
    local existing=$1 entered=""
    if ((INTERACTIVE)); then
        if [[ -n "$existing" ]]; then
            read -r -s -p "SMTP-Passwort (Enter behaelt den bestehenden Wert): " entered
            printf '\n'
            SMTP_PASSWORD=${entered:-$existing}
        else
            read -r -s -p "SMTP-Passwort: " SMTP_PASSWORD
            printf '\n'
        fi
    fi
}

read_cloudflare_token() {
    local existing=$1 entered=""
    if ((INTERACTIVE)); then
        if [[ -n "$existing" ]]; then
            read -r -s -p "Cloudflare API-Token (Enter behaelt den bestehenden Wert): " entered
            printf '\n'
            CLOUDFLARE_API_TOKEN=${entered:-$existing}
        else
            read -r -s -p "Cloudflare API-Token: " CLOUDFLARE_API_TOKEN
            printf '\n'
        fi
    fi
}

valid_port() { [[ $1 =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }
valid_high_port() { valid_port "$1" && ((10#$1 >= 1024)); }
valid_integer_range() { [[ $1 =~ ^[0-9]+$ ]] && ((10#$1 >= $2 && 10#$1 <= $3)); }
yes_value() { [[ ${1,,} =~ ^(y|yes|j|ja|true|1)$ ]]; }

derive_domain_values() {
    DOMAIN_TLD=${DOMAIN_TLD,,}
    DOMAIN_TLD=${DOMAIN_TLD#.}
    DOMAIN_TLD=${DOMAIN_TLD%.}
    DOMAIN_SUBDOMAIN=${DOMAIN_SUBDOMAIN,,}
    [[ "$DOMAIN_SUBDOMAIN" != "-" ]] || DOMAIN_SUBDOMAIN=""
    DOMAIN_SUBDOMAIN=${DOMAIN_SUBDOMAIN#.}
    DOMAIN_SUBDOMAIN=${DOMAIN_SUBDOMAIN%.}
    if [[ -n "$DOMAIN_SUBDOMAIN" ]]; then
        PORTAL_FQDN="${DOMAIN_SUBDOMAIN}.${DOMAIN_TLD}"
    else
        PORTAL_FQDN="$DOMAIN_TLD"
    fi
}

validate_configuration() {
    derive_domain_values
    [[ "$DOMAIN_TLD" == *.* && "$DOMAIN_TLD" != *..* ]] \
        || die "DOMAIN_TLD muss eine DNS-Basisdomain wie example.com sein."
    [[ "$DOMAIN_TLD" =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ ]] \
        || die "Ungueltige DNS-Basisdomain: ${DOMAIN_TLD}"
    [[ -z "$DOMAIN_SUBDOMAIN" || ( "$DOMAIN_SUBDOMAIN" != *..* && "$DOMAIN_SUBDOMAIN" =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ ) ]] \
        || die "Ungueltige optionale Subdomain: ${DOMAIN_SUBDOMAIN}"
    [[ "$PORTAL_FQDN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] \
        || die "Ungueltiger Portal-Hostname: ${PORTAL_FQDN}"
    [[ "$PORTAL_FQDN" == *.* ]] || die "Fuer TLS wird ein vollqualifizierter Hostname mit Punkt benoetigt."
    valid_high_port "$PORTAL_PORT" || die "Der Web-Port muss zwischen 1024 und 65535 liegen."
    valid_port "$BACKUP_SSH_PORT" || die "Der SSH-Port muss zwischen 1 und 65535 liegen."
    [[ "$PORTAL_PORT" != "$BACKUP_SSH_PORT" ]] || die "Web-Port und SSH-Port muessen unterschiedlich sein."
    [[ "$BACKUP_TARGET_HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] \
        || die "Ungueltiger Backup-Zielhostname: ${BACKUP_TARGET_HOSTNAME}"
    [[ "$ADMIN_USERNAME" =~ ^[A-Za-z][A-Za-z0-9_.-]{2,31}$ ]] || die "Ungueltiger Admin-Benutzername."
    [[ ${#ADMIN_PASSWORD} -ge 12 ]] || die "Das Admin-Passwort muss mindestens 12 Zeichen lang sein."
    valid_port "$SMTP_PORT" || die "Ungueltiger SMTP-Port."
    [[ -n "$SMTP_HOST" && -n "$SMTP_FROM" && -n "$SMTP_TO" ]] || die "SMTP-Host, Absender und Admin-E-Mail sind erforderlich."
    [[ "$SMTP_TO" != *,* && "$SMTP_TO" != *\;* && "$SMTP_TO" == *@*.* ]] \
        || die "SMTP_TO muss genau eine gueltige E-Mail-Adresse fuer den initialen Admin enthalten."
    if [[ -n "$SMTP_USERNAME" && -z "$SMTP_PASSWORD" ]]; then
        die "Bei gesetztem SMTP-Benutzernamen darf das SMTP-Passwort nicht leer sein."
    fi
    valid_integer_range "$CHECKER_INTERVAL_MINUTES" 5 1440 || die "Checker-Intervall: 5 bis 1440 Minuten."
    valid_integer_range "$MINIMUM_FREE_PERCENT" 1 99 || die "Freispeicher-Schwellwert: 1 bis 99 Prozent."
    valid_integer_range "$SNAPSHOT_RETENTION_DAYS" 1 3650 || die "Aufbewahrung: 1 bis 3650 Tage."
    valid_integer_range "$CLEANUP_RUN_HOUR" 0 23 || die "Cleanup-Stunde: 0 bis 23."
    case "${TLS_MODE,,}" in
        letsencrypt-dns-cloudflare)
            [[ "$ACME_EMAIL" == *@*.* ]] || die "Eine gueltige ACME_EMAIL ist fuer Let's Encrypt erforderlich."
            valid_integer_range "$ACME_DNS_TIMEOUT_SECONDS" 60 86400 || die "DNS-Timeout: 60 bis 86400 Sekunden."
            valid_integer_range "$ACME_DNS_POLL_SECONDS" 5 300 || die "DNS-Pollintervall: 5 bis 300 Sekunden."
            [[ -n "$ACME_DNS_RESOLVERS" ]] || die "Mindestens ein DNS-Resolver ist erforderlich."
            [[ "$ACME_DNS_RESOLVERS" =~ ^[A-Za-z0-9.,:_-]+$ ]] || die "Ungueltige Zeichen in ACME_DNS_RESOLVERS."
            ((${#CLOUDFLARE_API_TOKEN} >= 20)) || die "Cloudflare API-Token fehlt oder ist zu kurz."
            [[ -z "$CLOUDFLARE_ZONE_ID" || "$CLOUDFLARE_ZONE_ID" =~ ^[A-Fa-f0-9]{32}$ ]] || die "Cloudflare Zone-ID muss 32 Hex-Zeichen haben."
            valid_integer_range "$CLOUDFLARE_TTL" 60 86400 || [[ "$CLOUDFLARE_TTL" == "1" ]] || die "Cloudflare TTL muss 1 oder 60 bis 86400 sein."
            ;;
        letsencrypt-dns-manual|letsencrypt-dns)
            TLS_MODE="letsencrypt-dns-manual"
            [[ "$ACME_EMAIL" == *@*.* ]] || die "Eine gueltige ACME_EMAIL ist fuer Let's Encrypt erforderlich."
            valid_integer_range "$ACME_DNS_TIMEOUT_SECONDS" 60 86400 || die "DNS-Timeout: 60 bis 86400 Sekunden."
            valid_integer_range "$ACME_DNS_POLL_SECONDS" 5 300 || die "DNS-Pollintervall: 5 bis 300 Sekunden."
            [[ -n "$ACME_DNS_RESOLVERS" ]] || die "Mindestens ein DNS-Resolver ist erforderlich."
            [[ "$ACME_DNS_RESOLVERS" =~ ^[A-Za-z0-9.,:_-]+$ ]] || die "Ungueltige Zeichen in ACME_DNS_RESOLVERS."
            ;;
        letsencrypt-http)
            [[ "$ACME_EMAIL" == *@*.* ]] || die "Eine gueltige ACME_EMAIL ist fuer Let's Encrypt erforderlich."
            ;;
        existing)
            [[ -r "$TLS_CERT_PATH" && -r "$TLS_KEY_PATH" ]] || die "TLS-Zertifikat oder privater Schluessel ist nicht lesbar."
            ;;
        *) die "TLS_MODE muss letsencrypt-dns-cloudflare, letsencrypt-dns-manual, letsencrypt-http oder existing sein." ;;
    esac
}

toml_quote() {
    printf '%s' "$1" | python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read(), ensure_ascii=False))'
}

toml_array_from_csv() {
    local csv=$1 item first=1
    local -a items=()
    local old_ifs=$IFS
    IFS=',' read -r -a items <<<"$csv"
    IFS=$old_ifs
    printf '['
    for item in "${items[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [[ -n "$item" ]] || continue
        ((first)) || printf ', '
        toml_quote "$item"
        first=0
    done
    printf ']'
}

collect_configuration() {
    log "Konfiguration erfassen"
    local detected_fqdn detected_hostname existing_smtp_password existing_session_secret legacy_fqdn configured_zone
    detected_fqdn=$(hostname -f 2>/dev/null || hostname)
    detected_hostname=$(hostname)

    legacy_fqdn=${PORTAL_FQDN:-$(config_value "$CONFIG_FILE" acme domain "")}
    if [[ -z "$legacy_fqdn" ]]; then
        legacy_fqdn=$(config_value "$CONFIG_FILE" server allowed_hosts "$detected_fqdn")
        legacy_fqdn=${legacy_fqdn%%,*}
    fi
    configured_zone=$(config_value "$CONFIG_FILE" acme.cloudflare zone_name "")
    DOMAIN_TLD=${DOMAIN_TLD:-$(config_value "$CONFIG_FILE" domain tld "$configured_zone")}
    if [[ -z "$DOMAIN_TLD" ]]; then
        DOMAIN_TLD=$(python3 - "$legacy_fqdn" <<'PY'
import sys
labels = sys.argv[1].strip().strip(".").lower().split(".")
print(".".join(labels[-2:]) if len(labels) >= 2 else sys.argv[1])
PY
)
    fi
    DOMAIN_SUBDOMAIN=${DOMAIN_SUBDOMAIN:-$(config_value "$CONFIG_FILE" domain subdomain "")}
    if [[ -z "$DOMAIN_SUBDOMAIN" && "$legacy_fqdn" == *."$DOMAIN_TLD" && "$legacy_fqdn" != "$DOMAIN_TLD" ]]; then
        DOMAIN_SUBDOMAIN=${legacy_fqdn%."$DOMAIN_TLD"}
    fi
    derive_domain_values
    PORTAL_PORT=${PORTAL_PORT:-$(config_value "$CONFIG_FILE" server port "49180")}
    BACKUP_SSH_PORT=${BACKUP_SSH_PORT:-$(config_value "$CONFIG_FILE" onboarding backup_ssh_port "49150")}
    BACKUP_TARGET_HOSTNAME=${BACKUP_TARGET_HOSTNAME:-$(config_value "$CONFIG_FILE" onboarding remote_hostname "$detected_hostname")}
    ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
    SMTP_HOST=${SMTP_HOST:-$(database_setting_value "$CONFIG_FILE" smtp host "$(config_value "$CONFIG_FILE" smtp host "smtp.example.com")")}
    SMTP_PORT=${SMTP_PORT:-$(database_setting_value "$CONFIG_FILE" smtp port "$(config_value "$CONFIG_FILE" smtp port "25")")}
    SMTP_USERNAME=${SMTP_USERNAME:-$(database_setting_value "$CONFIG_FILE" smtp username "$(config_value "$CONFIG_FILE" smtp username "")")}
    SMTP_FROM=${SMTP_FROM:-$(database_setting_value "$CONFIG_FILE" smtp from_address "$(config_value "$CONFIG_FILE" smtp from_address "backup@example.com")")}
    SMTP_TO=${SMTP_TO:-$(database_setting_value "$CONFIG_FILE" smtp to "$(config_value "$CONFIG_FILE" smtp to "")")}
    CHECKER_INTERVAL_MINUTES=${CHECKER_INTERVAL_MINUTES:-$(config_value "$CONFIG_FILE" checker interval_minutes "60")}
    MINIMUM_FREE_PERCENT=${MINIMUM_FREE_PERCENT:-$(config_value "$CHECKER_CONFIG_FILE" storage minimum_free_percent "15")}
    SNAPSHOT_RETENTION_DAYS=${SNAPSHOT_RETENTION_DAYS:-$(config_value "$CHECKER_CONFIG_FILE" cleanup snapshot_retention_days "7")}
    CLEANUP_RUN_HOUR=${CLEANUP_RUN_HOUR:-$(config_value "$CHECKER_CONFIG_FILE" cleanup run_hour "23")}
    IMPORT_EXISTING_CLIENTS=${IMPORT_EXISTING_CLIENTS:-yes}
    ADMIN_PASSWORD=${ADMIN_PASSWORD:-}
    SMTP_PASSWORD=${SMTP_PASSWORD:-}
    CLOUDFLARE_API_TOKEN=${CLOUDFLARE_API_TOKEN:-}

    existing_smtp_password=$(database_setting_value "$CONFIG_FILE" smtp password "$(config_value "$CONFIG_FILE" smtp password "")")
    if ((!INTERACTIVE)) && [[ -z "$SMTP_PASSWORD" ]]; then
        SMTP_PASSWORD=$existing_smtp_password
    fi
    existing_session_secret=$(config_value "$CONFIG_FILE" security session_secret "")
    SESSION_SECRET=${SESSION_SECRET:-$existing_session_secret}
    if ((${#SESSION_SECRET} < 32)); then
        SESSION_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(48))')
    fi

    local configured_tls_cert configured_acme_mode
    configured_tls_cert=$(config_value "$CONFIG_FILE" server tls_cert "")
    configured_acme_mode=$(config_value "$CONFIG_FILE" acme mode "")
    if [[ "$configured_acme_mode" == "dns-cloudflare" ]]; then
        TLS_MODE=${TLS_MODE:-letsencrypt-dns-cloudflare}
    elif [[ "$configured_acme_mode" == "dns-manual" ]]; then
        TLS_MODE=${TLS_MODE:-letsencrypt-dns-manual}
    elif [[ "$configured_acme_mode" == "http-standalone" ]]; then
        TLS_MODE=${TLS_MODE:-letsencrypt-http}
    elif [[ -n "$configured_tls_cert" ]]; then
        if [[ "$configured_tls_cert" == /etc/letsencrypt/* ]]; then
            TLS_MODE=${TLS_MODE:-letsencrypt-dns-cloudflare}
        else
            TLS_MODE=${TLS_MODE:-existing}
        fi
    else
        TLS_MODE=${TLS_MODE:-letsencrypt-dns-cloudflare}
    fi
    ACME_EMAIL=${ACME_EMAIL:-$SMTP_TO}
    ACME_DNS_RESOLVERS=${ACME_DNS_RESOLVERS:-$(config_value "$CONFIG_FILE" acme resolvers "1.1.1.1,8.8.8.8")}
    ACME_DNS_TIMEOUT_SECONDS=${ACME_DNS_TIMEOUT_SECONDS:-$(config_value "$CONFIG_FILE" acme propagation_timeout_seconds "7200")}
    ACME_DNS_POLL_SECONDS=${ACME_DNS_POLL_SECONDS:-$(config_value "$CONFIG_FILE" acme poll_interval_seconds "15")}
    ACME_FORCE_REISSUE=${ACME_FORCE_REISSUE:-no}
    local existing_cloudflare_token configured_cloudflare_credentials
    configured_cloudflare_credentials=$(config_value "$CONFIG_FILE" acme.cloudflare credentials_file "$CLOUDFLARE_CREDENTIALS_FILE")
    existing_cloudflare_token=$(cloudflare_token_value "$configured_cloudflare_credentials")
    if [[ -z "$existing_cloudflare_token" ]]; then
        existing_cloudflare_token=$(database_setting_value "$CONFIG_FILE" cloudflare api_token "")
    fi
    if ((!INTERACTIVE)) && [[ -z "$CLOUDFLARE_API_TOKEN" ]]; then
        CLOUDFLARE_API_TOKEN=$existing_cloudflare_token
    fi
    CLOUDFLARE_ZONE_ID=${CLOUDFLARE_ZONE_ID:-$(database_setting_value "$CONFIG_FILE" cloudflare zone_id "$(config_value "$CONFIG_FILE" acme.cloudflare zone_id "")")}
    CLOUDFLARE_TTL=${CLOUDFLARE_TTL:-$(database_setting_value "$CONFIG_FILE" cloudflare ttl "$(config_value "$CONFIG_FILE" acme.cloudflare ttl "60")")}
    TLS_CERT_PATH=${TLS_CERT_PATH:-$(config_value "$CONFIG_FILE" server tls_cert "/etc/letsencrypt/live/${PORTAL_FQDN}/fullchain.pem")}
    TLS_KEY_PATH=${TLS_KEY_PATH:-$(config_value "$CONFIG_FILE" server tls_key "/etc/letsencrypt/live/${PORTAL_FQDN}/privkey.pem")}

    ask DOMAIN_TLD "DNS-Basisdomain und Cloudflare-Zone (z. B. example.com)"
    ask_optional DOMAIN_SUBDOMAIN "Optionale Portal-Subdomain (z. B. backup)"
    derive_domain_values
    ask PORTAL_PORT "Hoher HTTPS-Port"
    ask BACKUP_SSH_PORT "SSH-Port fuer eingehende Backups"
    ask BACKUP_TARGET_HOSTNAME "Erwarteter hostname-Wert dieses Backup-Ziels"
    ask ADMIN_USERNAME "Initialer/lokaler Admin-Benutzer"
    read_admin_password
    ask SMTP_HOST "SMTP-Host"
    ask SMTP_PORT "SMTP-Port"
    ask SMTP_USERNAME "SMTP-Benutzer (leer fuer anonymes SMTP)"
    read_smtp_password "$existing_smtp_password"
    ask SMTP_FROM "Mail-Absender"
    ask SMTP_TO "E-Mail-Adresse des initialen Admins"
    ask CHECKER_INTERVAL_MINUTES "Checker-Intervall in Minuten"
    ask MINIMUM_FREE_PERCENT "Alarmgrenze freier Zielspeicher in Prozent"
    ask SNAPSHOT_RETENTION_DAYS "Aufbewahrung persistenter Backups in Tagen"
    ask CLEANUP_RUN_HOUR "Taegliche Cleanup-Stunde (0-23)"
    ask_yes_no IMPORT_EXISTING_CLIENTS "Bestehende backup_*-Systembenutzer importieren?"
    ask TLS_MODE "TLS-Modus (letsencrypt-dns-cloudflare, letsencrypt-dns-manual, letsencrypt-http oder existing)"

    if [[ ${TLS_MODE,,} == letsencrypt-* ]]; then
        ACME_EMAIL=${ACME_EMAIL:-$SMTP_TO}
        ACME_EMAIL="${ACME_EMAIL#"${ACME_EMAIL%%[![:space:]]*}"}"
        ACME_EMAIL="${ACME_EMAIL%"${ACME_EMAIL##*[![:space:]]}"}"
        ask ACME_EMAIL "Let's-Encrypt-Kontaktadresse"
        if [[ ${TLS_MODE,,} == letsencrypt-dns-* || ${TLS_MODE,,} == "letsencrypt-dns" ]]; then
            ask ACME_DNS_RESOLVERS "DNS-Resolver fuer die Propagationspruefung, kommasepariert"
            ask ACME_DNS_TIMEOUT_SECONDS "Maximale Wartezeit auf den TXT-Eintrag in Sekunden"
            ask ACME_DNS_POLL_SECONDS "DNS-Pruefintervall in Sekunden"
            if [[ ${TLS_MODE,,} == "letsencrypt-dns-cloudflare" ]]; then
                read_cloudflare_token "$existing_cloudflare_token"
                ask CLOUDFLARE_ZONE_ID "Cloudflare Zone-ID (leer = automatisch erkennen)"
                ask CLOUDFLARE_TTL "Cloudflare TXT TTL in Sekunden"
            fi
            if [[ -r "/etc/letsencrypt/live/${PORTAL_FQDN}/fullchain.pem" ]]; then
                ask_yes_no ACME_FORCE_REISSUE "Vorhandenes Zertifikat jetzt per DNS-01 neu ausstellen?"
            fi
        fi
        TLS_CERT_PATH="/etc/letsencrypt/live/${PORTAL_FQDN}/fullchain.pem"
        TLS_KEY_PATH="/etc/letsencrypt/live/${PORTAL_FQDN}/privkey.pem"
    else
        ask TLS_CERT_PATH "Pfad zur TLS-Zertifikatskette"
        ask TLS_KEY_PATH "Pfad zum privaten TLS-Schluessel"
    fi

    validate_configuration
}

port_is_listening() {
    local port=$1
    ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$port$"
}

configure_backup_ssh_port() {
    log "OpenSSH fuer Backup-Port ${BACKUP_SSH_PORT} pruefen"
    install -d -m 0755 /etc/ssh/sshd_config.d
    if ! port_is_listening "$BACKUP_SSH_PORT"; then
        local -a ports=()
        local port
        while read -r port; do
            [[ "$port" =~ ^[0-9]+$ ]] && ports+=("$port")
        done < <(/usr/sbin/sshd -T 2>/dev/null | awk '$1 == "port" {print $2}')
        ports+=("$BACKUP_SSH_PORT")

        : >"${TEMP_DIR}/ssh-port.conf"
        printf '# Managed by RAVEN installer. Existing ports are retained.\n' >>"${TEMP_DIR}/ssh-port.conf"
        printf '%s\n' "${ports[@]}" | awk '!seen[$0]++ {print "Port " $0}' >>"${TEMP_DIR}/ssh-port.conf"
        install -o root -g root -m 0644 "${TEMP_DIR}/ssh-port.conf" "$SSH_DROPIN"
        /usr/sbin/sshd -t
        systemctl enable --now ssh.service
        systemctl restart ssh.service
        sleep 1
    else
        info "Port ${BACKUP_SSH_PORT}/tcp wird bereits von OpenSSH bedient."
    fi
    port_is_listening "$BACKUP_SSH_PORT" || die "OpenSSH lauscht nicht auf Port ${BACKUP_SSH_PORT}."
}

ufw_is_active() {
    LANG=C ufw status 2>/dev/null | grep -q '^Status: active$'
}

allow_ufw_port() {
    local port=$1 comment=$2
    if ufw_is_active; then
        ufw allow "${port}/tcp" comment "$comment" >/dev/null
        LANG=C ufw status | grep -Eq "(^|[[:space:]])${port}/tcp([[:space:]]|$)" \
            || die "UFW-Regel fuer Port ${port}/tcp konnte nicht verifiziert werden."
        info "UFW erlaubt ${port}/tcp (${comment})."
    else
        info "UFW ist inaktiv; es wurde nicht automatisch aktiviert."
    fi
}

configure_firewall() {
    log "Firewall-Regeln pruefen"
    allow_ufw_port "$BACKUP_SSH_PORT" "RAVEN backup SSH"
    allow_ufw_port "$PORTAL_PORT" "RAVEN portal HTTPS"
    if [[ ${TLS_MODE,,} == "letsencrypt-http" ]]; then
        allow_ufw_port 80 "Let's Encrypt HTTP-01 renewal"
    fi
}

provision_certificate() {
    log "TLS-Zertifikat pruefen"
    if [[ ${TLS_MODE,,} == "letsencrypt-dns-cloudflare" ]]; then
        install -d -o root -g root -m 0700 "$CONFIG_DIR"
        cat >"${TEMP_DIR}/cloudflare-acme.toml" <<EOF
[cloudflare]
api_token = $(toml_quote "$CLOUDFLARE_API_TOKEN")
api_base = "https://api.cloudflare.com/client/v4"
zone_id = $(toml_quote "$CLOUDFLARE_ZONE_ID")
ttl = ${CLOUDFLARE_TTL}
EOF
        cat >"${TEMP_DIR}/cloudflare-check.toml" <<EOF
[domain]
tld = $(toml_quote "$DOMAIN_TLD")
subdomain = $(toml_quote "$DOMAIN_SUBDOMAIN")

[server]
port = ${PORTAL_PORT}

[acme]
mode = "dns-cloudflare"

[acme.cloudflare]
credentials_file = $(toml_quote "${TEMP_DIR}/cloudflare-acme.toml")
zone_id = $(toml_quote "$CLOUDFLARE_ZONE_ID")
ttl = ${CLOUDFLARE_TTL}
EOF
        install -d -o root -g root -m 0755 "$APP_DIR"
        install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/domain_config.py" "$APP_DIR/domain_config.py"
        install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/runtime_config.py" "$APP_DIR/runtime_config.py"
        install -o root -g root -m 0755 "${PROJECT_ROOT}/portal/acme_dns_hook.py" "$APP_DIR/acme_dns_hook.py"
        /usr/bin/python3 "$APP_DIR/acme_dns_hook.py" cloudflare-check --config "${TEMP_DIR}/cloudflare-check.toml"
        install -o root -g root -m 0600 "${TEMP_DIR}/cloudflare-acme.toml" "$CLOUDFLARE_CREDENTIALS_FILE"
    fi
    if [[ ${TLS_MODE,,} == "letsencrypt-dns-cloudflare" || ${TLS_MODE,,} == "letsencrypt-dns-manual" || ${TLS_MODE,,} == "letsencrypt-dns" ]]; then
        install -d -o root -g root -m 0755 "$APP_DIR"
        install -d -o root -g root -m 0700 "$ACME_STATE_DIR"
        install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/domain_config.py" "$APP_DIR/domain_config.py"
        install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/runtime_config.py" "$APP_DIR/runtime_config.py"
        install -o root -g root -m 0755 "${PROJECT_ROOT}/portal/acme_dns_hook.py" "$APP_DIR/acme_dns_hook.py"
        install -o root -g root -m 0755 "${PROJECT_ROOT}/portal/acme_manager.py" "$APP_DIR/acme_manager.py"
        if [[ ! -r "$TLS_CERT_PATH" || ! -r "$TLS_KEY_PATH" ]] || yes_value "$ACME_FORCE_REISSUE"; then
            local auth_hook cleanup_hook
            local -a force_args=()
            if [[ -r "$TLS_CERT_PATH" ]] && yes_value "$ACME_FORCE_REISSUE"; then
                force_args+=("--force-renewal")
            fi
            local hook_config=""
            if [[ ${TLS_MODE,,} == "letsencrypt-dns-cloudflare" ]]; then
                hook_config="--config ${CLOUDFLARE_CREDENTIALS_FILE}"
            fi
            auth_hook="/usr/bin/python3 ${APP_DIR}/acme_dns_hook.py auth ${hook_config} --state-dir ${ACME_STATE_DIR} --timeout ${ACME_DNS_TIMEOUT_SECONDS} --interval ${ACME_DNS_POLL_SECONDS} --resolvers ${ACME_DNS_RESOLVERS}"
            cleanup_hook="/usr/bin/python3 ${APP_DIR}/acme_dns_hook.py cleanup ${hook_config} --state-dir ${ACME_STATE_DIR} --timeout ${ACME_DNS_TIMEOUT_SECONDS} --interval ${ACME_DNS_POLL_SECONDS} --resolvers ${ACME_DNS_RESOLVERS}"
            if [[ ${TLS_MODE,,} == "letsencrypt-dns-cloudflare" ]]; then
                info "Cloudflare legt den DNS-01-TXT-Eintrag automatisch an; das Skript wartet danach auf dessen Propagation."
            else
                info "Certbot erzeugt jetzt den DNS-01-Wert. Das Skript zeigt den erforderlichen TXT-Eintrag an und wartet auf dessen Propagation."
            fi
            certbot certonly --manual --preferred-challenges dns --non-interactive --agree-tos \
                --manual-auth-hook "$auth_hook" --manual-cleanup-hook "$cleanup_hook" \
                --keep-until-expiring "${force_args[@]}" --email "$ACME_EMAIL" --cert-name "$PORTAL_FQDN" --domains "$PORTAL_FQDN"
            if [[ ${TLS_MODE,,} == "letsencrypt-dns-cloudflare" ]]; then
                info "Die Challenge ist abgeschlossen; der Cloudflare-TXT-Eintrag wurde automatisch entfernt."
            else
                info "Die Challenge ist abgeschlossen. Der im Hook genannte TXT-Wert kann nach erfolgreicher Ausstellung entfernt werden."
            fi
        else
            info "Vorhandenes Let's-Encrypt-Zertifikat wird verwendet; künftige DNS-01-Erneuerungen verwaltet das Portal."
        fi
    elif [[ ${TLS_MODE,,} == "letsencrypt-http" ]]; then
        if [[ ! -r "$TLS_CERT_PATH" || ! -r "$TLS_KEY_PATH" ]]; then
            if port_is_listening 80; then
                die "Port 80 ist belegt. Fuer certbot --standalone bitte den Dienst stoppen oder TLS_MODE=existing verwenden."
            fi
            certbot certonly --standalone --non-interactive --agree-tos \
                --preferred-challenges http --keep-until-expiring \
                --email "$ACME_EMAIL" --domains "$PORTAL_FQDN"
        else
            info "Vorhandenes Let's-Encrypt-Zertifikat wird im HTTP-01-Modus verwendet."
        fi
    fi

    [[ -r "$TLS_CERT_PATH" && -r "$TLS_KEY_PATH" ]] || die "TLS-Dateien fehlen nach der Zertifikatsbereitstellung."
    openssl x509 -in "$TLS_CERT_PATH" -noout -checkend 0 >/dev/null \
        || die "Das TLS-Zertifikat ist abgelaufen oder ungueltig."
    openssl x509 -in "$TLS_CERT_PATH" -noout -checkhost "$PORTAL_FQDN" >/dev/null \
        || die "Das TLS-Zertifikat gilt nicht fuer ${PORTAL_FQDN}."

    local cert_key_hash private_key_hash
    cert_key_hash=$(openssl x509 -in "$TLS_CERT_PATH" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
    private_key_hash=$(openssl pkey -in "$TLS_KEY_PATH" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
    [[ -n "$cert_key_hash" && "$cert_key_hash" == "$private_key_hash" ]] \
        || die "TLS-Zertifikat und privater Schluessel passen nicht zusammen."
    unset CLOUDFLARE_API_TOKEN
}

write_configuration() {
    log "Sichere TOML-Konfiguration erzeugen"
    local acme_mode
    case "${TLS_MODE,,}" in
        letsencrypt-dns-cloudflare) acme_mode="dns-cloudflare" ;;
        letsencrypt-dns-manual|letsencrypt-dns) acme_mode="dns-manual" ;;
        letsencrypt-http) acme_mode="http-standalone" ;;
        existing) acme_mode="existing" ;;
    esac

    cat >"${TEMP_DIR}/portal.toml" <<EOF
[domain]
tld = $(toml_quote "$DOMAIN_TLD")
subdomain = $(toml_quote "$DOMAIN_SUBDOMAIN")

[server]
host = "0.0.0.0"
port = ${PORTAL_PORT}
tls_cert = $(toml_quote "$TLS_CERT_PATH")
tls_key = $(toml_quote "$TLS_KEY_PATH")

[acme]
mode = $(toml_quote "$acme_mode")
email = $(toml_quote "$ACME_EMAIL")
state_dir = "${ACME_STATE_DIR}"
lock_path = "/run/backup-portal-acme.lock"
hook = "${APP_DIR}/acme_dns_hook.py"
python = "${APP_DIR}/venv/bin/python"
certbot = "/usr/bin/certbot"
propagation_timeout_seconds = ${ACME_DNS_TIMEOUT_SECONDS}
poll_interval_seconds = ${ACME_DNS_POLL_SECONDS}
resolvers = $(toml_array_from_csv "$ACME_DNS_RESOLVERS")

[database]
path = "${DATA_DIR}/portal.db"

[paths]
backup_script = "${APP_DIR}/assets/backup_job.py"
bootstrap_script = "${APP_DIR}/assets/bootstrap_agent.py"
checker_state = "${CHECKER_DATA_DIR}/state.json"
home_root = "/home"

[checker]
enabled = true
interval_minutes = ${CHECKER_INTERVAL_MINUTES}
timeout_seconds = 1800
script = "${APP_DIR}/checker/backup_check.py"
config = "${CHECKER_CONFIG_FILE}"

[onboarding]
username_prefix = "backup_"
backup_ssh_port = ${BACKUP_SSH_PORT}
remote_hostname = $(toml_quote "$BACKUP_TARGET_HOSTNAME")
deployment_token_minutes = 15
default_schedule_hour = 2
default_schedule_minute = 0
default_interval_hours = 24
min_remote_free_bytes = 21474836480
database_split_threshold_bytes = 2147483648

[security]
session_hours = 12
session_secret = $(toml_quote "$SESSION_SECRET")
EOF

    cat >"${TEMP_DIR}/checker.toml" <<EOF
[monitor]
home_root = "/home"
user_glob = "backup_*"
# Fallback fuer Konten ohne Portal-Policy; sonst gilt das Intervall der Policy.
max_age_hours = 36
require_nonempty = true
check_volume_change = true
volume_timeout_seconds = 300
timestamp_formats = ["%Y%m%d", "%Y%m%d%H%M", "%Y%m%d%H%M%S", "%Y%m%d%H%M%S%f"]
mirror_folder_patterns = ["current_copy", "rsync_copy_*"]
ssh_activity_for_mirrors = true
ssh_journal_unit = "ssh.service"
ok_marker_name = ".backup-ok"
require_ok_file_for_users = ["backup_*"]
incomplete_grace_hours = 6
ignore = []

[smtp]
enabled = false
host = ""
port = 25
username = ""
password = ""
from_address = ""
to = []
starttls = false
timeout_seconds = 20

# Mailausloeser verwaltet das Portal unter "Checker" und uebergibt sie je Lauf.
[alerts]
state_file = "${CHECKER_DATA_DIR}/state.json"
reminder_hours = 24
mail_on_problem = true
mail_on_recovery = true
mail_on_clean_run = false
alarm_on_unchanged = false

[storage]
enabled = true
path = "/home"
minimum_free_percent = ${MINIMUM_FREE_PERCENT}

[cleanup]
enabled = true
run_hour = ${CLEANUP_RUN_HOUR}
legacy_file_retention_days = 5
legacy_file_patterns = ["*.tgz", "*.gz", "*.pst", "*.sql"]
delete_empty_directories = true
snapshot_name_digits = 17
snapshot_retention_days = ${SNAPSHOT_RETENTION_DAYS}
incomplete_snapshot_retention_hours = 48
minimum_snapshots_to_keep = 2
EOF

    local toml_validator="python3"
    if [[ -x "$APP_DIR/venv/bin/python" ]]; then
        toml_validator="$APP_DIR/venv/bin/python"
    fi
    "$toml_validator" - "${TEMP_DIR}/portal.toml" "${TEMP_DIR}/checker.toml" <<'PY'
import sys
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
for filename in sys.argv[1:]:
    with open(filename, "rb") as handle:
        tomllib.load(handle)
    print(f"    TOML gueltig: {filename}")
PY
}

install_application() {
    log "Portal-Anwendung installieren"
    install -d -o root -g root -m 0755 \
        "$APP_DIR" "$APP_DIR/assets" "$APP_DIR/checker" "$APP_DIR/static" "$APP_DIR/templates"
    install -d -o root -g root -m 0700 "$CONFIG_DIR" "$DATA_DIR" "$CHECKER_DATA_DIR"

    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/app.py" "$APP_DIR/app.py"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/run.py" "$APP_DIR/run.py"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/requirements.txt" "$APP_DIR/requirements.txt"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/README.md" "$APP_DIR/README.md"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/domain_config.py" "$APP_DIR/domain_config.py"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/runtime_config.py" "$APP_DIR/runtime_config.py"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/backup_schedule.py" "$APP_DIR/backup_schedule.py"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/mirror.py" "$APP_DIR/mirror.py"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/assets/bootstrap_agent.py" "$APP_DIR/assets/bootstrap_agent.py"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/backupscript/backup_job.py" "$APP_DIR/assets/backup_job.py"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/backup_check.py" "$APP_DIR/checker/backup_check.py"
    install -o root -g root -m 0755 "${PROJECT_ROOT}/portal/acme_dns_hook.py" "$APP_DIR/acme_dns_hook.py"
    install -o root -g root -m 0755 "${PROJECT_ROOT}/portal/acme_manager.py" "$APP_DIR/acme_manager.py"

    local source_file target_directory
    for target_directory in static templates; do
        while IFS= read -r -d '' source_file; do
            install -o root -g root -m 0644 "$source_file" "$APP_DIR/$target_directory/$(basename "$source_file")"
        done < <(find "${PROJECT_ROOT}/portal/${target_directory}" -maxdepth 1 -type f -print0)
    done

    if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
        python3 -m venv "$APP_DIR/venv"
    fi
    "$APP_DIR/venv/bin/python" -m pip install --disable-pip-version-check --upgrade pip wheel
    "$APP_DIR/venv/bin/python" -m pip install --disable-pip-version-check --requirement "$APP_DIR/requirements.txt"

    "$APP_DIR/venv/bin/python" - <<'PY'
import cryptography, fastapi, jinja2, multipart, uvicorn
print("    Python-Pakete erfolgreich importiert")
PY
}

backup_existing_state() {
    local stamp
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    if systemctl is-active --quiet "${APP_NAME}.service" 2>/dev/null; then
        SERVICE_WAS_ACTIVE=1
        systemctl stop "${APP_NAME}.service"
    fi
    if [[ -f "$CONFIG_FILE" ]]; then
        install -o root -g root -m 0600 "$CONFIG_FILE" "${CONFIG_FILE}.bak.${stamp}"
    fi
    if [[ -f "$CHECKER_CONFIG_FILE" ]]; then
        install -o root -g root -m 0600 "$CHECKER_CONFIG_FILE" "${CHECKER_CONFIG_FILE}.bak.${stamp}"
    fi
    if [[ -f "${DATA_DIR}/portal.db" ]]; then
        python3 - "${DATA_DIR}/portal.db" "${DATA_DIR}/portal.db.bak.${stamp}" <<'PY'
import sqlite3
import sys
source = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
target = sqlite3.connect(sys.argv[2])
with target:
    source.backup(target)
source.close()
target.close()
PY
        chown root:root "${DATA_DIR}/portal.db.bak.${stamp}"
        chmod 0600 "${DATA_DIR}/portal.db.bak.${stamp}"
    fi
}

install_configuration_and_service() {
    log "Konfiguration und systemd-Dienst aktivieren"
    backup_existing_state
    install -o root -g root -m 0600 "${TEMP_DIR}/portal.toml" "$CONFIG_FILE"
    install -o root -g root -m 0600 "${TEMP_DIR}/checker.toml" "$CHECKER_CONFIG_FILE"
    if [[ ! -f "${CHECKER_DATA_DIR}/state.json" ]]; then
        printf '{}\n' >"${CHECKER_DATA_DIR}/state.json"
    fi
    chown root:root "${CHECKER_DATA_DIR}/state.json"
    chmod 0600 "${CHECKER_DATA_DIR}/state.json"

    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/backup-portal.service" "$SERVICE_FILE"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/backup-portal-cert-renew.service" "$CERT_RENEW_SERVICE_FILE"
    install -o root -g root -m 0644 "${PROJECT_ROOT}/portal/backup-portal-cert-renew.timer" "$CERT_RENEW_TIMER_FILE"
    install -d -o root -g root -m 0755 "$(dirname "$CERTBOT_HOOK")"
    install -o root -g root -m 0755 "${PROJECT_ROOT}/portal/certbot-deploy-hook.sh" "$CERTBOT_HOOK"
    systemctl daemon-reload
}

ensure_admin() {
    log "SQLite initialisieren und Admin setzen"
    (
        cd "$APP_DIR"
        BACKUP_PORTAL_CONFIG="$CONFIG_FILE" "$APP_DIR/venv/bin/python" - \
            "$ADMIN_USERNAME" "$SMTP_HOST" "$SMTP_PORT" "$SMTP_USERNAME" "$SMTP_FROM" "$SMTP_TO" \
            3<<<"$ADMIN_PASSWORD" 4<<<"$SMTP_PASSWORD" <<'PY'
import json
import os
import sys
import app

username = sys.argv[1]
smtp_host, smtp_port, smtp_username, smtp_from, smtp_to = sys.argv[2:7]
password = os.fdopen(3, encoding="utf-8").read()
if password.endswith("\n"):
    password = password[:-1]
smtp_password = os.fdopen(4, encoding="utf-8").read()
if smtp_password.endswith("\n"):
    smtp_password = smtp_password[:-1]
app.init_db()
with app.db() as connection:
    current_smtp = connection.execute("SELECT password_ciphertext FROM smtp_settings WHERE id=1").fetchone()
    smtp_ciphertext = current_smtp["password_ciphertext"] if current_smtp else ""
    if smtp_password:
        smtp_ciphertext = app.encrypt_deployment_token(smtp_password)
    admin_email = smtp_to.strip()
    connection.execute(
        "INSERT INTO smtp_settings(id,enabled,host,port,username,password_ciphertext,from_address,"
        "recipients_json,timeout_seconds,updated_at) VALUES(1,1,?,?,?,?,?,?,20,?) "
        "ON CONFLICT(id) DO UPDATE SET enabled=1,host=excluded.host,port=excluded.port,"
        "username=excluded.username,password_ciphertext=excluded.password_ciphertext,"
        "from_address=excluded.from_address,recipients_json=excluded.recipients_json,updated_at=excluded.updated_at",
        (smtp_host, int(smtp_port), smtp_username, smtp_ciphertext, smtp_from, "[]", app.now_iso()),
    )
    existing = connection.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    encoded = app.hash_password(password)
    if existing:
        connection.execute(
            "UPDATE users SET password_hash=?,role='admin',email=?,receive_notifications=1,active=1 WHERE id=?",
            (encoded, admin_email, existing["id"]),
        )
        connection.execute("DELETE FROM sessions WHERE user_id=?", (existing["id"],))
        action = "installer.admin_update"
    else:
        connection.execute(
            "INSERT INTO users(username,display_name,password_hash,role,email,receive_notifications,created_at) "
            "VALUES(?,?,?,?,?,1,?)",
            (username, "Administrator", encoded, "admin", admin_email, app.now_iso()),
        )
        action = "installer.admin_create"
    connection.execute(
        "INSERT INTO audit_log(user_id,action,target,details,ip,created_at) VALUES(NULL,?,?,?,?,?)",
        (action, username, "local root installer", "127.0.0.1", app.now_iso()),
    )
print(f"    Admin bereit: {username}")
PY
    )
    unset ADMIN_PASSWORD SMTP_PASSWORD
}

import_existing_clients() {
    if yes_value "$IMPORT_EXISTING_CLIENTS"; then
        log "Bestehende backup_*-Benutzer importieren"
        (
            cd "$APP_DIR"
            BACKUP_PORTAL_CONFIG="$CONFIG_FILE" "$APP_DIR/venv/bin/python" app.py import-clients
        )
    fi
}

start_and_verify() {
    log "Portal starten und Readiness pruefen"
    systemctl enable --now "${APP_NAME}.service"
    SERVICE_WAS_ACTIVE=0

    local response="" attempt
    for attempt in {1..30}; do
        if response=$(curl --fail --silent --show-error \
            --connect-timeout 3 --max-time 8 \
            --resolve "${PORTAL_FQDN}:${PORTAL_PORT}:127.0.0.1" \
            "https://${PORTAL_FQDN}:${PORTAL_PORT}/readyz" 2>/dev/null); then
            if [[ "$response" == *'"status":"ready"'* || "$response" == *'"status": "ready"'* ]]; then
                printf '%s\n' "$response"
                break
            fi
        fi
        sleep 1
    done
    if [[ "$response" != *'"status":"ready"'* && "$response" != *'"status": "ready"'* ]]; then
        systemctl status "${APP_NAME}.service" --no-pager >&2 || true
        journalctl -u "${APP_NAME}.service" -n 50 --no-pager >&2 || true
        die "Readiness-Pruefung ist fehlgeschlagen."
    fi

    systemctl is-active --quiet "${APP_NAME}.service" || die "Portal-Dienst ist nicht aktiv."
    port_is_listening "$PORTAL_PORT" || die "Portal lauscht nicht auf Port ${PORTAL_PORT}."
    if [[ ${TLS_MODE,,} == "letsencrypt-dns-cloudflare" || ${TLS_MODE,,} == "letsencrypt-dns-manual" || ${TLS_MODE,,} == "letsencrypt-dns" ]]; then
        systemctl enable --now backup-portal-cert-renew.timer
        systemctl is-active --quiet backup-portal-cert-renew.timer || die "ACME-Erneuerungstimer ist nicht aktiv."
    else
        systemctl disable --now backup-portal-cert-renew.timer 2>/dev/null || true
    fi
}

print_summary() {
    cat <<EOF

Installation erfolgreich abgeschlossen.

  Portal:          https://${PORTAL_FQDN}:${PORTAL_PORT}
  Admin:           ${ADMIN_USERNAME}
  Portal-Service:  systemctl status backup-portal
  Portal-Log:      journalctl -u backup-portal
  Zertifikate:     https://${PORTAL_FQDN}:${PORTAL_PORT}/certificates
  ACME-Timer:      $(if [[ ${TLS_MODE,,} == letsencrypt-dns-* || ${TLS_MODE,,} == "letsencrypt-dns" ]]; then echo aktiv; else echo inaktiv; fi)
  SSH-Backup-Port: ${BACKUP_SSH_PORT}/tcp
  Konfiguration:   ${CONFIG_FILE}
  Checker-Config:  ${CHECKER_CONFIG_FILE}
  SQLite:          ${DATA_DIR}/portal.db
  Liveness:        https://${PORTAL_FQDN}:${PORTAL_PORT}/livez
  Readiness:       https://${PORTAL_FQDN}:${PORTAL_PORT}/readyz

Das Admin-Passwort wurde nicht ausgegeben und liegt nur als scrypt-Hash in SQLite.
EOF
}

main() {
    require_root
    require_supported_os
    require_project_files
    TEMP_DIR=$(mktemp -d /tmp/backup-portal-install.XXXXXX)
    chmod 0700 "$TEMP_DIR"

    install_dependencies
    collect_configuration
    configure_backup_ssh_port
    configure_firewall
    provision_certificate
    install_application
    write_configuration
    install_configuration_and_service
    ensure_admin
    import_existing_clients
    start_and_verify
    print_summary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
