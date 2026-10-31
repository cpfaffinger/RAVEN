#!/usr/bin/env bash
# Runs on the portal server; started by deploy/deploy.sh from a staged copy.
set -euo pipefail
umask 077

stage="$1"
sha="$2"
fqdn="$3"
portal_port="$4"
app=/opt/backup-portal
database=/var/lib/backup-portal/portal.db
backups="$app/.deploy-backups"
keep=5

die() { echo "deploy: $*" >&2; exit 1; }

active_runs() {
    "$app/venv/bin/python" - "$database" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
print(sum(connection.execute(query).fetchone()[0] for query in (
    "SELECT COUNT(*) FROM mirror_runs WHERE status='running'",
    "SELECT COUNT(*) FROM checker_runs WHERE status='running'",
    "SELECT COUNT(*) FROM policy_cleanup_runs WHERE status='running'",
    "SELECT COUNT(*) FROM backup_commands WHERE status IN ('claimed','running')",
)))
PY
}

ready() {
    curl -fsSk -o /dev/null --max-time 5 \
        --resolve "$fqdn:$portal_port:127.0.0.1" "https://$fqdn:$portal_port/readyz"
}

wait_ready() {
    for _ in $(seq 1 30); do
        ready 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

install_tree() {
    local source="$1"
    install -o root -g root -m 0644 "$source"/portal/*.py "$app/"
    install -o root -g root -m 0755 "$source/portal/acme_dns_hook.py" "$source/portal/acme_manager.py" "$app/"
    install -o root -g root -m 0644 "$source/portal/requirements.txt" "$app/requirements.txt"
    install -o root -g root -m 0644 "$source/portal/assets/bootstrap_agent.py" "$app/assets/bootstrap_agent.py"
    install -o root -g root -m 0644 "$source/backupscript/backup_job.py" "$app/assets/backup_job.py"
    install -o root -g root -m 0644 "$source/backup_check.py" "$app/checker/backup_check.py"
    rm -rf "$app/templates" "$app/static"
    cp -a "$source/portal/templates" "$source/portal/static" "$app/"
    chown -R root:root "$app/templates" "$app/static"
    chmod -R go= "$app/templates" "$app/static"
}

snapshot() {
    local target="$1"
    mkdir -p "$target/portal/assets" "$target/backupscript"
    cp -a "$app"/*.py "$app/requirements.txt" "$target/portal/"
    cp -a "$app/assets/bootstrap_agent.py" "$target/portal/assets/"
    cp -a "$app/assets/backup_job.py" "$target/backupscript/"
    cp -a "$app/checker/backup_check.py" "$target/"
    cp -a "$app/templates" "$app/static" "$target/portal/"
}

active="$(active_runs)"
[ "$active" = 0 ] || die "$active Läufe sind aktiv, Deploy abgebrochen"
"$app/venv/bin/python" -m compileall -q "$stage/portal" "$stage/backup_check.py" "$stage/backupscript" \
    || die "Syntaxfehler im Stand $sha"

mkdir -p "$backups"
previous="$backups/$(date -u +%Y%m%dT%H%M%SZ)-before-$sha"
snapshot "$previous"
"$app/venv/bin/python" - "$database" "$database.pre-$sha" <<'PY'
import sqlite3
import sys

source, target = sqlite3.connect(sys.argv[1]), sqlite3.connect(sys.argv[2])
source.backup(target)
PY
chmod 0600 "$database.pre-$sha"

cmp -s "$stage/portal/requirements.txt" "$app/requirements.txt" \
    || "$app/venv/bin/pip" install -q -r "$stage/portal/requirements.txt"
install_tree "$stage"
systemctl restart backup-portal

if ! wait_ready; then
    echo "deploy: /readyz antwortet nicht, setze den vorherigen Stand zurück" >&2
    install_tree "$previous"
    systemctl restart backup-portal
    wait_ready || die "Auch der vorherige Stand startet nicht"
    die "Stand $sha zurückgerollt"
fi

# shellcheck disable=SC2012 # the names are generated above and contain no blanks
ls -1dt "$backups"/* | tail -n +$((keep + 1)) | xargs -r rm -rf --
# shellcheck disable=SC2012
ls -1t "$database".pre-* | tail -n +$((keep + 1)) | xargs -r rm -f --
echo "deploy: $sha läuft, Rücksprung in $previous"
