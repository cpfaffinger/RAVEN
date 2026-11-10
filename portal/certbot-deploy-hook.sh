#!/bin/sh
set -eu

if systemctl is-enabled --quiet raven.service; then
    systemctl try-restart raven.service
fi
