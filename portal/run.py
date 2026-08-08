#!/usr/bin/env python3
"""Start the portal using the listener and TLS values from its TOML config."""

import os
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

import uvicorn


config_path = os.environ.get("BACKUP_PORTAL_CONFIG", "/etc/backup-portal/config.toml")
with open(config_path, "rb") as handle:
    config = tomllib.load(handle)

server = config["server"]
uvicorn.run(
    "app:app",
    host=str(server.get("host", "0.0.0.0")),
    port=int(server.get("port", 49180)),
    ssl_certfile=str(server["tls_cert"]),
    ssl_keyfile=str(server["tls_key"]),
    proxy_headers=False,
    workers=1,
)
