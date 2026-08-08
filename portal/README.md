# RAVEN Backup-Portal

RAVEN steht für **Recovery, Archiving, Verification, Events & Notification**.

Das Portal wird als root-privilegierter, gehärteter systemd-Dienst betrieben. Root ist notwendig, um isolierte `backup_*`-Systemkonten und deren `authorized_keys` anzulegen. Es läuft direkt mit TLS auf dem in TOML konfigurierten hohen Port.

## Bedienung

1. Als Portal-Administrator anmelden.
2. Unter **Policies** das Sicherungsmodell anlegen: MariaDB-Datenbanken und MariaDB-Benutzer/Rechte können unabhängig aktiviert werden; Pfade werden als aktuelle `sync`-Kopie oder persistentes `tar.zst`-Archiv definiert.
3. Unter **Neuen Server onboarden** den Client, genau eine Policy, Zeitplan sowie Mail- und Logging-Optionen anlegen.
4. In den Clientdetails „Ein-Befehl-Deployment“ auswählen und festlegen, ob direkt ein vollständiges Backup starten soll.
5. Den angezeigten `curl`-Befehl als root auf genau diesem Quellserver ausführen.

Der Bootstrap akzeptiert Debian und Ubuntu, prüft die benötigten Programme und installiert fehlende Backup-Abhängigkeiten idempotent über `apt-get` – insbesondere `zstd`, `rsync`, OpenSSH, `tar`, `cron`, CA-Zertifikate und gegebenenfalls `python3-tomli`. MariaDB selbst wird nicht installiert. Anschließend erzeugt er den privaten Ed25519-Schlüssel ausschließlich auf der Quelle, registriert nur den öffentlichen Schlüssel, installiert Agent und Konfiguration, verwaltet einen markierten SSH-/Cron-Block und führt Preflight plus Portal-Heartbeat aus. Ist die Sofortstart-Option aktiv, läuft anschließend im selben Curl-Aufruf das vollständige Backup. Danach pollt der Agent minütlich die zentrale Queue; Tageszeitplan und manuelle Trigger werden vom Portal gesteuert. Ein interner Agent-Lock verhindert parallele Läufe.

Die beim Queuen gültige Policy wird unveränderlich im Auftrag gespeichert. Policy-Änderungen wirken deshalb nur auf neu gequeuete Backups. Ein Client kann immer nur genau einer Policy zugeordnet sein.

Policies dürfen vollständig leer sein. Ohne Dateisystempfade und mit beiden deaktivierten MariaDB-Optionen überträgt der Agent keine Nutzdaten, bleibt aber per Polling sichtbar und erzeugt für geplante Kontrollläufe weiterhin Status, Manifest, Laufprotokoll und `.backup-ok`.

Die Portal-Einstellungen werden als versionierte, fertig konfektionierte TOML-Datei im Curl-Onboarding an die Quelle geliefert. Dazu gehören Loglevel, lokale Ausgabe, dauerhafter Portal-Upload, Traceback, Loggrößenlimit sowie getrennte Erfolgs- und Fehlermails. Nach jedem tatsächlich gestarteten Backup überträgt der Agent sein begrenztes Laufprotokoll und eine kompakte Ergebnisstruktur an das Portal. Diese Daten liegen in SQLite und bleiben erhalten, wenn das eigentliche Backup später rotiert oder gelöscht wird.

Ein noch unbenutzter Curl-Befehl kann aus den Clientdetails bis zum Ablauf erneut angezeigt oder aktiv widerrufen werden. Dafür liegt das Deployment-Token zusätzlich zum Prüfdigest ausschließlich symmetrisch verschlüsselt in SQLite; nach Verwendung, Widerruf oder Ablauf ist kein Wiederabruf mehr möglich.

## Betrieb

```sh
systemctl status backup-portal
journalctl -u backup-portal
systemctl restart backup-portal
```

Domain und Onboarding-Basiswerte werden in SQLite verwaltet und stehen admin-only unter **Konfiguration** bereit; die TOML liefert nur Bootstrap-Defaults und bootkritische Listener-, TLS-, Pfad- und Secret-Werte. Basisdomain und optionale Subdomain bestimmen gemeinsam Portal-URL, Curl-Onboarding, Agent-Endpunkte, SSH-Ziel, Trusted Hosts und Zertifikatsnamen. Domainwechsel bleiben vorgemerkt, bis das neue Zertifikat erfolgreich ausgestellt wurde. Im Modus `dns-cloudflare` legt der Certbot-Auth-Hook den erforderlichen DNS-01-TXT-Record per Cloudflare API an, persistiert den Status für das admin-only Menü **Zertifikate**, wartet auf öffentliche Propagation und löscht exakt die erzeugte Record-ID nach der Validierung. Token, Zone-ID und TTL werden im Webinterface verwaltet und verschlüsselt in SQLite gespeichert; der Token-/Zone-Lesetest kann dort ohne DNS-Änderung ausgelöst werden. Eine vorhandene Legacy-Credentials-Datei wird einmalig importiert und anschließend entfernt. `backup-portal-cert-renew.timer` prüft täglich auf erforderliche Erneuerungen. Nach einer Ausstellung wird der Portalprozess neu gestartet und lädt das rotierte Zertifikat. `dns-manual` bleibt als Provider-unabhängiger Fallback erhalten.

SMTP wird nach der Erstinitialisierung zentral aus der SQLite-Tabelle `smtp_settings` gelesen. Das Passwort liegt dort mit dem Portal-Master-Secret verschlüsselt. Änderungen erfolgen admin-only unter **SMTP** und erhöhen die Agent-Konfigurationsversion. Checker und Agent verwenden ausschließlich Plain-SMTP; STARTTLS und SMTPS werden nicht aufgerufen.

Monitoring verwendet `/livez` für die reine Prozess-Liveness und `/readyz` für die Einsatzbereitschaft von SQLite, Tokenverschlüsselung, Ziel-Home und Agent-Assets. `/healthz` bleibt als Readiness-Alias kompatibel. Das vollständige Betriebshandbuch ist nach Anmeldung unter **Handbuch** im Portal verfügbar.

Die admin-only Seite **Prozesse** zeigt die RAVEN-Dienste und internen Worker sowie die Ergebnisse der letzten Backup-Aufträge, Checker-, ACME- und Cloudflare-Prüfläufe.

Lokale Portalbenutzer werden im Menü **Benutzer** als `admin` oder `viewer` verwaltet. Admins dürfen Clients onboarden und Benutzer ändern; Viewer haben ausschließlich lesenden Zugriff. Passwörter werden mit scrypt, Sitzungs-, Deployment- und Agent-Tokens nur als SHA-256-Hash in `/var/lib/backup-portal/portal.db` gespeichert.

Der admin-only **Backup Explorer** durchsucht bestehende Client-Homes read-only. Er unterstützt Einzeldownloads aus normalen Dateien sowie aus `.tar`, `.tar.gz`/`.tgz` und `.tar.zst`/`.tzst`. Pfade bleiben strikt im jeweiligen Backup-Home, Symlinks werden nicht geöffnet und jeder Download wird auditiert.

Der zentrale Checker läuft als eigener Worker innerhalb des Portalprozesses. Aktivierung und Intervall sowie normale, erzwungene, Dry-Run- und SMTP-Prüfungen werden unter **Checker** gesteuert. SQLite verhindert überlappende Läufe und hält die letzten 100 Ergebnisse; der frühere Checker-Cronjob wird nicht mehr benötigt.

## Relevante Dateien

- `/opt/backup-portal`: Anwendung und Bootstrap-/Agent-Assets
- `/opt/backup-portal/checker/backup_check.py`: vom Portal verwalteter Checker
- `/opt/backup-portal/acme_{manager,dns_hook}.py`: DNS-01-Anforderung, Status und Propagationsprüfung
- `/etc/backup-portal/backup-check.toml`: root-only Checker-Basiskonfiguration ohne SMTP-Secret, Modus `0600`
- `/etc/backup-portal/config.toml`: root-only Portal-Basiskonfiguration und internes Master-Secret, Modus `0600`
- `/var/lib/backup-portal/portal.db`: Benutzer, Tokens, Audit- und Agentereignisse, Modus `0600`
- `/etc/systemd/system/backup-portal.service`: systemd-Dienst
- `/etc/letsencrypt/renewal-hooks/deploy/restart-backup-portal`: TLS-Renewal-Hook
- `/var/lib/backup-portal/acme`: root-only Challenge- und Laufstatus
- `/etc/systemd/system/backup-portal-cert-renew.{service,timer}`: DNS-01-Erneuerung
