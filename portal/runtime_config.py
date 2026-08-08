#!/usr/bin/env python3
"""Load portal-owned runtime settings from SQLite with TOML bootstrap fallbacks."""

from __future__ import annotations

import copy
import sqlite3
from pathlib import Path
from typing import Any


SETTING_COLUMNS = (
    "domain_tld",
    "domain_subdomain",
    "username_prefix",
    "backup_ssh_port",
    "remote_hostname",
    "deployment_token_minutes",
    "default_schedule_hour",
    "default_schedule_minute",
    "min_remote_free_bytes",
    "database_split_threshold_bytes",
)


def bootstrap_settings(config: dict[str, Any]) -> dict[str, Any]:
    domain = config.get("domain", {}) if isinstance(config.get("domain"), dict) else {}
    onboarding = config.get("onboarding", {}) if isinstance(config.get("onboarding"), dict) else {}
    return {
        "domain_tld": str(domain.get("tld", "")).strip().lower().strip("."),
        "domain_subdomain": str(domain.get("subdomain", "")).strip().lower().strip("."),
        "username_prefix": str(onboarding.get("username_prefix", "backup_")),
        "backup_ssh_port": int(onboarding.get("backup_ssh_port", 22)),
        "remote_hostname": str(onboarding.get("remote_hostname", "backup")),
        "deployment_token_minutes": int(onboarding.get("deployment_token_minutes", 15)),
        "default_schedule_hour": int(onboarding.get("default_schedule_hour", 2)),
        "default_schedule_minute": int(onboarding.get("default_schedule_minute", 0)),
        "min_remote_free_bytes": int(onboarding.get("min_remote_free_bytes", 20 * 1024**3)),
        "database_split_threshold_bytes": int(
            onboarding.get("database_split_threshold_bytes", 2 * 1024**3)
        ),
    }


def database_settings(config: dict[str, Any]) -> dict[str, Any]:
    database = config.get("database", {}) if isinstance(config.get("database"), dict) else {}
    path = Path(str(database.get("path", "")))
    if not path or not path.is_file():
        return {}
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute("SELECT * FROM portal_settings WHERE id=1").fetchone()
        finally:
            connection.close()
    except (OSError, sqlite3.Error):
        return {}
    if not row:
        return {}
    values = {column: row[column] for column in SETTING_COLUMNS}
    keys = set(row.keys())
    values["domain_change_pending"] = bool(row["domain_change_pending"]) if "domain_change_pending" in keys else False
    values["pending_domain_tld"] = str(row["pending_domain_tld"] or "") if "pending_domain_tld" in keys else ""
    values["pending_domain_subdomain"] = str(row["pending_domain_subdomain"] or "") if "pending_domain_subdomain" in keys else ""
    return values


def effective_settings(config: dict[str, Any], *, prefer_pending_domain: bool = False) -> dict[str, Any]:
    values = bootstrap_settings(config)
    values.update(database_settings(config))
    if prefer_pending_domain and values.get("domain_change_pending"):
        values["domain_tld"] = values["pending_domain_tld"]
        values["domain_subdomain"] = values["pending_domain_subdomain"]
    return values


def runtime_config(config: dict[str, Any], *, prefer_pending_domain: bool = False) -> dict[str, Any]:
    """Return a copy with database-owned domain/onboarding sections overlaid."""
    result = copy.deepcopy(config)
    settings = effective_settings(config, prefer_pending_domain=prefer_pending_domain)
    result["domain"] = {
        "tld": settings["domain_tld"],
        "subdomain": settings["domain_subdomain"],
    }
    result["onboarding"] = {
        column: settings[column]
        for column in SETTING_COLUMNS
        if column not in {"domain_tld", "domain_subdomain"}
    }
    return result
