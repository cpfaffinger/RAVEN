#!/usr/bin/env bash
# Ship the committed and pushed state of RAVEN to the production portal.
#
#   RAVEN_SSH_TARGET=root@backup.example.com RAVEN_SSH_KEY=~/.ssh/key deploy/deploy.sh
#
# Optional: RAVEN_SSH_PORT (49150), RAVEN_PORTAL_PORT (49180).
set -euo pipefail

die() { echo "deploy: $*" >&2; exit 1; }

: "${RAVEN_SSH_TARGET:?RAVEN_SSH_TARGET fehlt, zum Beispiel root@backup.example.com}"
ssh_port="${RAVEN_SSH_PORT:-49150}"
portal_port="${RAVEN_PORTAL_PORT:-49180}"
ssh_args=(-p "$ssh_port" -o BatchMode=yes)
[ -n "${RAVEN_SSH_KEY:-}" ] && ssh_args+=(-i "$RAVEN_SSH_KEY")

cd "$(git rev-parse --show-toplevel)"
[ -z "$(git status --porcelain)" ] || die "Arbeitsverzeichnis ist nicht sauber"
git fetch -q origin
git merge-base --is-ancestor HEAD origin/master || die "HEAD ist noch nicht auf origin/master"

sha="$(git rev-parse --short HEAD)"
fqdn="${RAVEN_SSH_TARGET#*@}"
stage="/tmp/raven-deploy-$sha"

echo "deploy: $sha nach $fqdn"
git archive --format=tar HEAD portal backupscript/backup_job.py backup_check.py deploy \
    | ssh "${ssh_args[@]}" "$RAVEN_SSH_TARGET" "rm -rf '$stage' && mkdir -m 0700 '$stage' && tar -xf - -C '$stage'"
ssh "${ssh_args[@]}" "$RAVEN_SSH_TARGET" \
    "trap \"rm -rf '$stage'\" EXIT; bash '$stage/deploy/remote-install.sh' '$stage' '$sha' '$fqdn' '$portal_port'"
