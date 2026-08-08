#!/bin/sh
set -eu

if systemctl is-enabled --quiet backup-portal.service; then
    systemctl try-restart backup-portal.service
fi
