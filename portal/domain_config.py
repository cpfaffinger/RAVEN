#!/usr/bin/env python3
"""Resolve the portal domain and all derived URLs from one config section."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit


DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")


def _normalize(value: Any) -> str:
    return str(value or "").strip().lower().strip(".")


def resolve_domain_config(config: dict[str, Any]) -> dict[str, Any]:
    domain = config.get("domain", {})
    domain = domain if isinstance(domain, dict) else {}
    server = config.get("server", {})
    server = server if isinstance(server, dict) else {}

    tld = _normalize(domain.get("tld"))
    subdomain = _normalize(domain.get("subdomain"))
    legacy_fqdn = ""
    if not tld:
        acme = config.get("acme", {})
        acme = acme if isinstance(acme, dict) else {}
        cloudflare = acme.get("cloudflare", {})
        cloudflare = cloudflare if isinstance(cloudflare, dict) else {}
        tld = _normalize(cloudflare.get("zone_name"))
        legacy_fqdn = _normalize(acme.get("domain"))
        if not legacy_fqdn:
            allowed = server.get("allowed_hosts", [])
            if isinstance(allowed, list) and allowed:
                legacy_fqdn = _normalize(allowed[0])
        if not legacy_fqdn:
            legacy_fqdn = _normalize(urlsplit(str(server.get("public_base_url", ""))).hostname)
        if not tld and legacy_fqdn:
            labels = legacy_fqdn.split(".")
            tld = ".".join(labels[-2:]) if len(labels) >= 2 else legacy_fqdn
        if not subdomain and legacy_fqdn and legacy_fqdn != tld and legacy_fqdn.endswith("." + tld):
            subdomain = legacy_fqdn[: -(len(tld) + 1)]

    if not tld or "." not in tld or not DOMAIN_RE.fullmatch(tld):
        raise ValueError("[domain].tld muss eine gueltige DNS-Basisdomain sein")
    if subdomain and not DOMAIN_RE.fullmatch(subdomain):
        raise ValueError("[domain].subdomain ist ungueltig")
    fqdn = f"{subdomain}.{tld}" if subdomain else tld
    if len(fqdn) > 253 or any(not label or len(label) > 63 for label in fqdn.split(".")):
        raise ValueError("abgeleiteter Portal-FQDN ist ungueltig")
    port = int(server.get("port", 443))
    if not 1 <= port <= 65535:
        raise ValueError("[server].port ist ungueltig")
    authority = fqdn if port == 443 else f"{fqdn}:{port}"
    return {
        "tld": tld,
        "subdomain": subdomain,
        "fqdn": fqdn,
        "public_base_url": f"https://{authority}",
        "port": port,
    }
