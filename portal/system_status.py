"""What the operating system reports about certificates and systemd units."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import ACME_STATE_DIR, CONFIG, application_settings


def read_acme_state(name: str) -> dict[str, Any]:
    if name not in {"challenges.json", "job.json"}:
        return {}
    path = ACME_STATE_DIR / name
    try:
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return {}


def certificate_details() -> dict[str, Any]:
    managed_path = Path(f"/etc/letsencrypt/live/{application_settings()['fqdn']}/fullchain.pem")
    certificate_path = managed_path if managed_path.is_file() else Path(str(CONFIG["server"]["tls_cert"]))
    result: dict[str, Any] = {"path": str(certificate_path), "available": False}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
        try:
            sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        result.update(
            {
                "available": True,
                "subject": certificate.subject.rfc4514_string(),
                "issuer": certificate.issuer.rfc4514_string(),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_remaining": max(0, int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)),
                "expired": not_after <= datetime.now(timezone.utc),
                "sans": sans,
                "serial": format(certificate.serial_number, "X"),
                "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(":").upper(),
            }
        )
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def systemd_active(unit: str) -> bool:
    try:
        return subprocess.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", unit],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


MANAGED_SYSTEMD_UNITS = (
    "backup-portal.service",
    "backup-portal-cert-renew.timer",
    "backup-portal-cert-renew.service",
)


def systemd_unit_details(unit: str) -> dict[str, Any]:
    if unit not in MANAGED_SYSTEMD_UNITS:
        raise ValueError("Nicht verwaltete systemd Unit")
    details = {
        "name": unit,
        "kind": "systemd",
        "status": "unknown",
        "result": "Nicht verfügbar",
        "started_at": "",
        "finished_at": "",
        "details": "",
    }
    try:
        process = subprocess.run(
            [
                "/usr/bin/systemctl", "show", unit, "--no-pager",
                "--property=ActiveState,SubState,Result,ExecMainStatus,ActiveEnterTimestamp,InactiveEnterTimestamp",
            ],
            capture_output=True, text=True, timeout=10, check=False,
        )
        values = dict(
            line.split("=", 1) for line in process.stdout.splitlines() if "=" in line
        )
        active = values.get("ActiveState", "unknown")
        sub = values.get("SubState", "unknown")
        result = values.get("Result", "") or ("success" if active == "active" else active)
        details.update(
            {
                "status": "success" if active == "active" else "failure" if active == "failed" else "unknown",
                "result": result,
                "started_at": values.get("ActiveEnterTimestamp", ""),
                "finished_at": values.get("InactiveEnterTimestamp", ""),
                "details": f"{active}/{sub} · Exit {values.get('ExecMainStatus', '–')}",
            }
        )
        if process.returncode != 0:
            details["details"] = (process.stderr or details["details"])[:500]
    except (OSError, subprocess.TimeoutExpired) as exc:
        details["details"] = f"{type(exc).__name__}: {exc}"
    return details
