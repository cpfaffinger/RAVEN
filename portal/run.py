#!/usr/bin/env python3
"""Start the portal using the listener and TLS values from its TOML config."""

import os
from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

import uvicorn
from runtime_config import runtime_config


config_path = os.environ.get("BACKUP_PORTAL_CONFIG", "/etc/backup-portal/config.toml")
with open(config_path, "rb") as handle:
    config = tomllib.load(handle)
config = runtime_config(config)

server = config["server"]
if config.get("acme", {}).get("mode") in {"dns-manual", "dns-cloudflare"}:
    from domain_config import resolve_domain_config

    managed_domain = str(resolve_domain_config(config)["fqdn"])
    managed_cert = Path(f"/etc/letsencrypt/live/{managed_domain}/fullchain.pem")
    managed_key = Path(f"/etc/letsencrypt/live/{managed_domain}/privkey.pem")
    if managed_cert.is_file() and managed_key.is_file():
        server = dict(server)
        server["tls_cert"] = str(managed_cert)
        server["tls_key"] = str(managed_key)
uvicorn.run(
    "app:app",
    host=str(server.get("host", "0.0.0.0")),
    port=int(server.get("port", 49180)),
    ssl_certfile=str(server["tls_cert"]),
    ssl_keyfile=str(server["tls_key"]),
    proxy_headers=False,
    workers=1,
)
