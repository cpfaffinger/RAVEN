# RAVEN

**Recovery, Archiving, Verification, Events & Notification** ist eine selbst gehostete Plattform für Backup-Orchestrierung, Statusüberwachung, Wiederherstellung und Benachrichtigung.

RAVEN verbindet ein TLS-geschütztes Verwaltungsportal mit einem schlanken Python-Agenten. Backup-Quellen werden per Einmal-Curl-Befehl onboarded, erhalten eine zentral verwaltete Policy und streamen Archive direkt per SSH auf das Zielsystem. Eine externe Datenbank oder ein vorgeschalteter Webserver ist nicht erforderlich.

## Funktionen

- Policy-basierte Sicherung von Dateisystempfaden als Current Sync oder persistentes `tar.zst`
- zentral gepflegte Wunschzeit und Backup-Intervall je Policy, die der Agent bei jedem Abruf live übernimmt
- je Policy einstellbar, bei welchen Backup-Ereignissen eine Mail entsteht, und je Checker-Lauf, bei welchen Prüfergebnissen
- MariaDB-Dumps einschließlich optionaler Benutzer und Rechte
- zentrales Scheduling mit zufälligem Startversatz, Laufstatus, Protokolle, Rotation und Speicherwarnungen
- Erkennung unveränderter Sicherungen über SHA-256-Prüfsummen statt über die Byte-Größe
- Backup Explorer für Verzeichnisse, Zstandard-Archive und einzelne Downloads
- lokale Benutzer und Rollen, kurzlebige Deployment-Tokens sowie isolierte SSH-Zielkonten
- integriertes SQLite, Plain-SMTP-Benachrichtigungen und Let's Encrypt per Cloudflare- oder manueller DNS-01-Challenge
- Replikation des gesamten Bestands auf beliebig viele Spiegelserver mit eigenem Intervall und eigener Aufbewahrung
- Aktivitätsfeed auf der Übersicht über eingegangene Backups, Checkerläufe und Verwaltungsaktionen
- Liveness- und Readiness-Endpunkte für externes Monitoring

Dieses Repository enthält drei zusammengehörige Komponenten:

- `backupscript/backup_job.py`: Agent für direkte SSH-Backups von `/etc`, `/home` und optional MariaDB.
- `backup_check.py`: zentraler, zustandsbehafteter Backup- und Speicherplatz-Checker.
- `portal/`: öffentlich erreichbares, TLS-geschütztes Onboarding- und Statusportal.

Das Portal modelliert wiederverwendbare Backup-Policies. Jeder Server besitzt genau eine Policy; jeder konfigurierte Pfad wird entweder als aktuelle `sync`-Kopie oder als direkt gestreamtes `tar.zst` gesichert. Alle persistenten MariaDB- und Dateisystem-Sicherungen sind Zstandard-komprimiert. Jeder Queue-Auftrag enthält einen unveränderlichen Policy-Snapshot, damit spätere Änderungen laufende oder bereits wartende Backups nicht beeinflussen. Eine bestehende Policy lässt sich in der Detailansicht als Vorlage duplizieren – die Kopie übernimmt Zeitplan, Mailereignisse, MariaDB-Optionen und alle Pfadregeln, bleibt aber zunächst ohne Serverzuweisung. Nicht mehr zugewiesene Policies können Administratoren dort ebenso sicher löschen; historische Auftragssnapshots bleiben erhalten.

Produktionspfade:

- Backup-Agent: `/root/backup` mit `/root/backup-job.toml`
- Checker: `/root/backup_check.py` mit `/root/backup-check.toml`
- Portal: `/opt/backup-portal`, Konfiguration `/etc/backup-portal/config.toml`
- Portal-Service: `backup-portal.service`

Der Zielserver führt den Checker als überlappungsgeschützten Portal-Worker aus. Zeitplan, manuelle Checks, Dry-Runs, Force-Reports und SMTP-Prüfungen werden im Webinterface verwaltet; ein separater Checker-Cronjob ist nicht erforderlich.

Die Beispielkonfigurationen enthalten ausschließlich Platzhalter. Deployment- und Agent-Tokens werden nur gehasht in SQLite gespeichert; private SSH-Schlüssel entstehen ausschließlich auf dem jeweiligen Quellserver.

## Sicherheitsmodell und Secrets

RAVEN ist für einen dedizierten Backup-Zielserver vorgesehen. Das Portal läuft bewusst als `root`, weil es isolierte Linux-Zielkonten und deren `authorized_keys` verwaltet. Betreibe es nicht gemeinsam mit nicht vertrauenswürdigen Workloads und beschränke Portal- und SSH-Port zusätzlich über Host- oder Netzwerk-Firewalls.

Alle vom Betreiber verwalteten Secrets lassen sich im Webinterface setzen oder rotieren:

- Portal-Benutzerpasswörter unter **Benutzer**
- SMTP-Benutzer und -Passwort unter **SMTP**
- Cloudflare API-Token unter **Zertifikate**; der Wert wird nach dem Speichern nie wieder angezeigt
- Deployment- und Agent-Tokens werden vom Portal erzeugt und nicht als Klartext in SQLite gespeichert

Das interne Session-/Verschlüsselungssecret wird bei der Installation zufällig erzeugt und root-only gespeichert. SMTP-Passwort und Cloudflare-Token liegen ausschließlich verschlüsselt in SQLite; die TOML-Dateien enthalten nach abgeschlossener Installation keine Betreiber-Zugangsdaten. Die `.gitignore` schließt typische Secret-, Schlüssel-, Datenbank- und Laufzeitdateien aus.

SMTP ist absichtlich auf unverschlüsseltes Plain-SMTP ohne STARTTLS oder SMTPS beschränkt. Verwende dafür ausschließlich einen vertrauenswürdigen internen SMTP-Relay beziehungsweise einen anderweitig geschützten Netzwerkpfad; Anmeldedaten und Mailinhalt sind auf einem ungeschützten Transportweg sonst mitlesbar.

## Vollautomatische Installation des Zielservers

### Voraussetzungen

Der Zielserver benötigt:

- Debian 12 oder neuer beziehungsweise Ubuntu 22.04 oder neuer
- `root`-Zugriff und funktionierenden Internetzugang für APT, Python-Pakete und optional Let's Encrypt
- einen öffentlichen DNS-A/AAAA-Eintrag des Portal-Hostnamens auf den Zielserver
- einen erreichbaren hohen TCP-Port für HTTPS, standardmäßig `49180`
- einen erreichbaren TCP-Port für eingehende Backup-SSH-Verbindungen, standardmäßig `49150`
- bei `letsencrypt-dns-cloudflare` ein auf die betreffende Zone begrenztes Cloudflare-API-Token mit `Zone DNS Edit`; für automatische Zone-Erkennung zusätzlich `Zone Read`
- beim manuellen Fallback `letsencrypt-dns-manual` Schreibzugriff auf die DNS-Zone für den jeweils angezeigten TXT-Eintrag; Port 80 und ein lokaler Webserver sind in beiden DNS-Modi nicht erforderlich
- nur beim alternativen `letsencrypt-http` zusätzlich TCP-Port `80` für HTTP-01-Ausstellung und Erneuerung
- SMTP-Zugangsdaten und eine E-Mail-Adresse für den initialen Administrator

Der Installer ergänzt den konfigurierten SSH-Port, entfernt aber keine bestehenden SSH-Ports. Ist UFW bereits aktiv, werden die benötigten Regeln idempotent ergänzt. Eine inaktive Firewall wird bewusst nicht automatisch aktiviert, damit kein bestehender Remote-Zugang ausgesperrt wird. Bei einer vorgelagerten Cloud-Firewall oder Security Group müssen dieselben Ports dort separat erlaubt werden.

### 1. Repository auf den Zielserver übertragen

Das vollständige Repository muss auf dem Zielserver vorhanden sein. Der Installer verwendet Dateien aus `portal/`, `backupscript/` und dem Repository-Root. Beispiel mit Git:

```sh
git clone https://github.com/cpfaffinger/RAVEN.git /root/raven
cd /root/raven
```

Alternativ kann das Arbeitsverzeichnis per SCP oder RSYNC übertragen werden. Beispielkonfigurationen dürfen angepasst werden, produktive Kennwörter gehören jedoch nicht in das Repository.

### 2. Interaktive Installation starten

Auf einem frischen oder bereits eingerichteten Zielserver wird die vollständige Installation als `root` gestartet:

```sh
sudo bash install.sh
```

Der Assistent installiert und validiert zuerst sämtliche System- und Python-Abhängigkeiten. Anschließend fragt er folgende Einstellungen ab:

| Einstellung | Bedeutung | Standard |
| --- | --- | --- |
| DNS-Basisdomain | Zentrale Domain und Cloudflare-Zone, z. B. `example.com` | vorhandene Konfiguration bzw. erkannter Hostname |
| Portal-Subdomain | Optionaler Präfix, z. B. `backup`; leer verwendet die Basisdomain direkt | aus vorhandener Konfiguration |
| HTTPS-Port | Hoher Port des Webportals | `49180` |
| Backup-SSH-Port | SSH-Zielport der Backup-Agenten | `49150` |
| Zielhostname | Erwartete Ausgabe von `hostname` auf dem Backupserver | automatisch erkannt |
| Admin-Benutzer und Passwort | Erstes lokales Portal-Administratorkonto | `admin`, Passwort mindestens 12 Zeichen |
| SMTP | Host, Port, Benutzer, Passwort und Absender; die initiale Admin-E-Mail wird als erster Empfänger aktiviert, Transport ist fest Plain-SMTP | vorhandene Werte bzw. Vorbelegung |
| Checker-Intervall | Abstand zentraler Backupprüfungen | `60` Minuten |
| Freispeichergrenze | Alarm, wenn der freie Anteil darunter fällt | `15` Prozent |
| Aufbewahrung | Alter persistenter Backup-Snapshots bis zur Rotation | `7` Tage |
| Cleanup-Stunde | Lokale Stunde für die tägliche Rotation | `23` Uhr |
| Bestandsimport | Import vorhandener `backup_*`-Systemkonten | aktiviert |
| TLS-Modus | Cloudflare-DNS-Automatik, manueller DNS-Fallback, HTTP-01 oder vorhandene Zertifikatsdateien | `letsencrypt-dns-cloudflare` |

Das Admin-Passwort wird verdeckt abgefragt. Das SMTP-Passwort kann bei einer erneuten Installation durch eine leere Eingabe unverändert übernommen werden.

SMTP wird bei der Initialisierung in die eingebettete SQLite-Datenbank übernommen und danach im Webinterface zentral verwaltet; das Passwort ist mit dem Portal-Master-Secret verschlüsselt. Empfänger werden ausschließlich unter **Benutzer** über E-Mail-Adresse und **Mails erhalten** gesteuert. Wann überhaupt eine Mail entsteht, steht bei den auslösenden Stellen: Backup-Ereignisse in der Policy, Prüfergebnisse unter **Checker**. Nur aktive, freigeschaltete Benutzer erhalten Berichte. Checker laden die Liste bei jedem Lauf; Agenten übernehmen Änderungen beim nächsten Poll als atomare Konfigurationsaktualisierung. Beide Versandwege verwenden bewusst ausschließlich Plain-SMTP ohne STARTTLS oder SMTPS.

Domain und Onboarding-Werte werden bei der Erstinstallation aus den Assistentenangaben in die eingebettete SQLite-Datenbank übernommen und danach admin-only unter **Konfiguration** verwaltet. Der resultierende FQDN gilt zentral für Portal- und Curl-Links, Agent-Endpunkte, SSH-Onboarding, Trusted Hosts, Let’s Encrypt und die Cloudflare-Zone. Ein Domainwechsel wird zunächst vorgemerkt und erst nach erfolgreicher Ausstellung des passenden Zertifikats atomar aktiviert. Nur Listeneradresse/-port, TLS-Bootstrap-Pfade, Dateipfade und Master-Secret bleiben als bootkritische Werte in der root-only TOML.

### 3. Automatisch ausgeführte Installationsschritte

Nach der Abfrage erledigt das Skript automatisch:

- Bereitstellung der Anwendung unter `/opt/backup-portal` in einer isolierten Python-Umgebung
- Erzeugung minimierter root-only TOML-Basiskonfigurationen ohne SMTP- oder Cloudflare-Zugangsdaten
- Initialisierung bzw. Migration der eingebetteten SQLite-Datenbank
- Anlage oder Aktualisierung des lokalen Admin-Kontos
- optionalen Import vorhandener `backup_*`-Systembenutzer
- Konfiguration eines zusätzlichen OpenSSH-Ports, ohne bestehende SSH-Ports zu entfernen
- UFW-Freigaben, sofern UFW bereits aktiv ist; eine inaktive Firewall wird nicht ungefragt aktiviert
- Let's-Encrypt-DNS-01 mit sichtbarem TXT-Record und Propagations-Wartephase, optional HTTP-01 oder vorhandene TLS-Dateien
- täglichen systemd-Erneuerungstimer und Portalansicht für Zertifikat, Challenge und Certbot-Ergebnis
- Aktivierung des gehärteten `backup-portal.service`
- abschließende Liveness-, Readiness-, Port- und Dienstprüfung

Die SQLite-Datenbank liegt unter `/var/lib/backup-portal/portal.db`; ein externer Datenbankserver ist nicht erforderlich. Eine bestehende Datenbank wird migriert und nicht ersetzt. Vor Änderungen legt der Installer konsistente Zeitstempel-Backups von Datenbank und Konfiguration an. Bei einer erneuten Ausführung bleibt das Session-Secret erhalten; das eingegebene Admin-Passwort wird bewusst aktualisiert und vorhandene Sitzungen dieses Benutzers werden beendet.

### 4. Installation verifizieren

Am Ende gibt der Installer Portal-URL und relevante Pfade aus. Zusätzlich können die Prüfungen manuell wiederholt werden:

```sh
systemctl status backup-portal --no-pager
journalctl -u backup-portal -n 100 --no-pager
curl --fail https://backup.example.com:49180/livez
curl --fail https://backup.example.com:49180/readyz
```

`/livez` prüft den laufenden Webprozess. `/readyz` prüft zusätzlich SQLite, Scheduler, Checker, Ziel-Home, Tokenverschlüsselung und benötigte Agent-Dateien. Der Hostname und Port in den Beispielen müssen durch die gewählten Werte ersetzt werden.

Danach im Browser `https://<Portal-Hostname>:<HTTPS-Port>` öffnen und mit dem während der Installation angelegten Admin anmelden. Die sinnvolle Reihenfolge im Portal ist:

1. Unter **Policies** eine Backup-Policy anlegen oder die Standard-Policy prüfen.
2. Unter **Neuen Server onboarden** Quelle, Policy, Logging und Mailverhalten festlegen; Wunschzeit und Intervall kommen aus der Policy.
3. In den Clientdetails ein Deployment-Token erzeugen.
4. Den angezeigten Curl-Befehl einmalig als `root` auf dem Quellserver ausführen.
5. Agent-Readiness, ersten Portal-Poll und später das Ergebnis des geplanten Backups im Dashboard kontrollieren.

Ein erneutes Deployment ist idempotent: vorhandene RAVEN-Schlüssel werden wiederverwendet. Historische `pulseone_backup_*`-Identitäten werden ohne Schlüsselrotation in den aktuellen `raven_backup_*`-Pfad übernommen, und der öffentliche Schlüssel wird stets neu aus dem privaten Schlüssel abgeleitet.

### Nicht-interaktive Installation

Für automatisierte Installationen steht `sudo -E bash install.sh --non-interactive` zur Verfügung. Die erforderlichen und optionalen Umgebungsvariablen zeigt `bash install.sh --help` an. Geheimnisse sollten dabei aus einer geschützten Deployment-Umgebung kommen und nicht in Shell-History oder Repository abgelegt werden.

Beispiel mit verdeckter Kennworteingabe:

```sh
read -r -s -p "Admin-Passwort: " ADMIN_PASSWORD; export ADMIN_PASSWORD; echo
read -r -s -p "SMTP-Passwort: " SMTP_PASSWORD; export SMTP_PASSWORD; echo
export DOMAIN_TLD="example.com"
export DOMAIN_SUBDOMAIN="backup"
export ACME_EMAIL="admin@example.com"
export SMTP_HOST="smtp.example.com"
export SMTP_PORT="2525"
export SMTP_USERNAME="backup-notification"
export SMTP_FROM="backup@example.com"
export SMTP_TO="admin@example.com"
sudo --preserve-env=DOMAIN_TLD,DOMAIN_SUBDOMAIN,ACME_EMAIL,ADMIN_PASSWORD,SMTP_PASSWORD,SMTP_HOST,SMTP_PORT,SMTP_USERNAME,SMTP_FROM,SMTP_TO \
  bash install.sh --non-interactive
unset ADMIN_PASSWORD SMTP_PASSWORD
```

Für `TLS_MODE=existing` müssen zusätzlich `TLS_CERT_PATH` und `TLS_KEY_PATH` auf eine lesbare Zertifikatskette und den dazugehörigen unverschlüsselten privaten Schlüssel zeigen. Das Zertifikat muss zum Portal-Hostname passen.

### Let's Encrypt über DNS-01

`letsencrypt-dns-cloudflare` ist der empfohlene Modus und benötigt keinen lokalen Nginx, Apache oder Listener auf Port 80. Der Installer prüft zuerst das Cloudflare-Token und ermittelt die Zone anhand der optional angegebenen Zone-ID oder automatisch anhand des Zertifikatsnamens. Derselbe gefahrlose Token-/Zone-Lesetest kann später im Menü **Zertifikate** erneut ausgeführt werden; Ergebnis und Laufzeit erscheinen auch unter **Prozesse**. Certbot erzeugt anschließend einen DNS-01-Token; der Hook legt exakt diesen TXT-Record über die Cloudflare API an, wartet auf die Sichtbarkeit über alle konfigurierten Resolver und löscht exakt die zurückgelieferte Record-ID nach der Validierung wieder.

Die admin-only Seite **Prozesse** fasst Portal-Dienst, Scheduler, Checker-Worker, Zertifikatstimer und -dienst sowie die Historien von Backup-Aufträgen, Checker-Läufen, ACME und Cloudflare-Tests zusammen. Sie zeigt bewusst nur von RAVEN verwaltete Abläufe und keine vollständige Betriebssystem-Prozessliste.

Das Token wird bei der Erstinstallation verdeckt abgefragt, nach der Zertifikatsausstellung verschlüsselt in SQLite übernommen und aus der temporären Credentials-Datei entfernt. Danach werden Token, optionale Zone-ID und TTL ausschließlich unter **Zertifikate** verwaltet. Das Portal zeigt weder Token noch API-Header an. Empfohlen ist ein eigenes API-Token, das auf genau die Zertifikatszone beschränkt ist. Bei gesetzter Zone-ID genügt `Zone DNS Edit`; für die automatische Zonensuche wird zusätzlich `Zone Read` benötigt. Globale API-Keys werden nicht unterstützt.

Der Datensatz hat dieses Schema:

```text
Typ:  TXT
Name: _acme-challenge.backup.example.com
Wert: <vom Installer oder Portal angezeigter ACME-Wert>
```

Jede reguläre DNS-01-Erneuerung erzeugt einen neuen Wert. Der tägliche `backup-portal-cert-renew.timer` prüft, ob Certbot eine Erneuerung verlangt. Sobald eine neue Challenge läuft, zeigt das admin-only Menü **Zertifikate** TXT-Name, TXT-Wert, Cloudflare-Status, Propagationsstatus, Resolver und Cleanup-Ergebnis. Anlage, Prüfung und Entfernung des Records laufen unbeaufsichtigt. Nach erfolgreicher Ausstellung wird das Portal neu gestartet, damit Uvicorn das rotierte Zertifikat lädt.

Existiert beim Setup bereits ein Zertifikat, kann der Assistent es unverändert übernehmen oder sofort kontrolliert per DNS-01 neu ausstellen. Im nicht-interaktiven Modus erzwingt `ACME_FORCE_REISSUE=yes` diese Migration und wartet ebenfalls auf den neuen TXT-Eintrag.

Für DNS-Zonen außerhalb von Cloudflare bleibt `letsencrypt-dns-manual` verfügbar. In diesem Modus zeigt das Portal den jeweils neuen TXT-Wert an und wartet auf dessen manuelle Anlage; Ausstellung, Prüfung, Ablage und Reload laufen danach automatisch weiter.

```sh
systemctl status backup-portal-cert-renew.timer
journalctl -u backup-portal-cert-renew.service
```

## Backupzeit und Intervall

Wunschzeit und Intervall gehören zur Backup-Policy und gelten damit für alle Server, die diese Policy verwenden. Unter **Policies** werden Stunde, Minute und Intervall gesetzt, unter **Konfiguration** die Vorbelegung für neu angelegte Policies.

Die Wunschzeit ist der Anker des Musters. Bei 24 Stunden ist genau ein Backup pro Tag zu dieser Uhrzeit fällig, bei sechs Stunden zusätzlich alle sechs Stunden ab diesem Anker. Erlaubt sind ausschließlich Teiler von 24 Stunden und ganze Vielfache von 24 Stunden bis zu einer Woche; damit bleibt der Anker über Tagesgrenzen hinweg stabil.

Der optionale **Startversatz** verteilt die Server um die Wunschzeit: Bei ± 15 Minuten startet jeder Server zu einem eigenen, aber gleichbleibenden Zeitpunkt zwischen 01:45 und 02:15, sodass nicht alle Quellen gleichzeitig auf den Zielserver schreiben. Der Versatz wird aus Server und Termin abgeleitet und ist deshalb reproduzierbar; er ist auf zwei Stunden und zusätzlich auf ein Viertel des Intervalls begrenzt, damit sich benachbarte Termine nicht überschneiden. Ein Backup, das irgendwo im Fenster gelaufen ist, erfüllt den Termin – ein vorgezogener Force-Lauf wird also nicht wiederholt.

Der zentrale Scheduler queued einen Auftrag, sobald der laufende Termin offen ist, also seit dem Termin noch kein erfolgreiches Backup vorliegt. Der Agent prüft dieselbe Regel anschließend selbst:

- Bei jedem Poll liefert das Portal Wunschzeit, Intervall, den laufenden Termin und den Zeitpunkt des letzten Erfolgs mit. Eine geänderte Policy wirkt deshalb ab dem nächsten Abruf, ohne dass ein Client neu ausgerollt werden muss.
- Der Agent vergleicht das Portalergebnis mit seinem lokalen Zustand unter `/var/lib/raven-backup/` und lehnt einen Auftrag ab, solange der Termin bereits durch ein erfolgreiches Backup erfüllt ist. Der Auftrag erscheint dann als `SKIPPED`.
- Nur ein ausdrücklich erzwungener Auftrag umgeht die Prüfung: das Kontrollkästchen **Intervall ignorieren (Force)** in den Clientdetails oder `--force` beim direkten Aufruf des Agenten.

Auch das Agent-Skript selbst wird über denselben Kanal aktuell gehalten: Der Agent meldet die Prüfsumme seiner Datei, und das Portal liefert bei Abweichung die aktuelle Fassung aus. Sie wird geprüft, atomar geschrieben und ab dem folgenden Lauf verwendet.

Diese Selbstaktualisierung kann erst greifen, wenn auf der Quelle einmal ein Agent mit dieser Fähigkeit liegt. Quellserver, die noch mit einer älteren Fassung onboarded wurden, brauchen daher genau einmal ein erneutes Deployment über den Curl-Befehl; danach kommen weitere Agentversionen automatisch. Bis dahin bleibt der Zeitplan trotzdem wirksam, weil bereits der zentrale Scheduler nur zum fälligen Termin einen Auftrag erzeugt – die zusätzliche Prüfung auf dem Client fehlt lediglich.

Die Frist des Checkers folgt dem Intervall der Policy: Er alarmiert nach dem Anderthalbfachen des Intervalls, für den Tagesplan also weiterhin nach 36 Stunden. Ein Eintrag unter `max_age_hours_by_user` in `backup-check.toml` bleibt eine bewusste manuelle Ausnahme und hat Vorrang.

## Spiegelserver

Der Zielserver hält die Sicherungen so lange vor, wie es seine Rotation zulässt. Für eine längere Historie und eine zweite Kopie repliziert RAVEN den gesamten Bestand aus `/home` per rsync auf beliebig viele entfernte Spiegel. Verwaltet werden sie admin-only unter **Spiegelserver**.

Repliziert werden ausschließlich die Zielkonten des Backupsystems, also die Ordner unterhalb des Home-Roots, die mit dem konfigurierten Benutzerpräfix beginnen. Alles andere im Home-Root – Freigaben, Handablagen, fremde Benutzerordner – bleibt außen vor. Hat ein früherer Lauf solche Ordner bereits kopiert, bleiben sie auf dem Spiegel unverändert liegen und werden im Laufprotokoll benannt; RAVEN löscht auf einem fremden Server nichts von sich aus.

Je Ziel werden Hostname, SSH-Port, Benutzer, Zielpfad und ein privater OpenSSH-Schlüssel hinterlegt. Der Schlüssel liegt mit dem Portal-Master-Secret verschlüsselt in SQLite, wird nach dem Speichern nie wieder angezeigt und existiert während eines Laufs nur als root-only Datei unterhalb von `/run`, die danach wieder verschwindet.

Vor dem ersten Lauf muss der **Hostschlüssel** des Ziels gepinnt werden; der Knopf holt ihn per `ssh-keyscan` und zeigt den Fingerabdruck an. Repliziert wird ausschließlich mit `StrictHostKeyChecking=yes` gegen genau diesen Eintrag, und eine geänderte Adresse verwirft ihn wieder. Ohne Schlüsselpaar läuft kein Ziel an.

Jedes Ziel hat sein eigenes **Intervall**, seine eigenen **rsync-Optionen** und seine eigene **Aufbewahrung**. So entstehen unterschiedlich lange Historien nebeneinander – etwa ein Spiegel über acht und ein zweiter über dreißig Tage:

| Einstellung | Bedeutung |
| --- | --- |
| Intervall | Stunden zwischen zwei Replikationsläufen dieses Ziels |
| rsync-Optionen | Übertragungsverhalten, z. B. `-a --delete --stats` oder `-avz --bwlimit=50M` |
| Aufbewahrung | Tage, nach denen Laufordner auf dem Spiegel entfernt werden; `0` entfernt nichts |

Die rsync-Optionen sind operatorseitig, laufen aber gegen eine Freigabeliste: erlaubt sind Optionen, die beschreiben *was* übertragen wird, niemals solche, die bestimmen *wie* die Gegenseite erreicht wird. `-e`, `--rsh`, `--rsync-path`, `--files-from` und Verwandte werden abgelehnt, weil sie fremde Programme starten könnten; Quelle, Ziel und SSH-Transport setzt RAVEN selbst.

Die Aufbewahrung greift ausschließlich auf Verzeichnisse, die exakt wie ein Backup-Lauf eines Zielkontos aussehen (`<ziel>/backup_*/<lauf-id>`). Alles andere auf dem Spiegel bleibt unberührt, auch `current`-Spiegel und fremde Verzeichnisse.

### Drei Betriebsmuster

Wie weit die Historie eines Spiegels reicht, ergibt sich aus dem Zusammenspiel von rsync-Optionen und Intervall. Der Zielserver selbst rotiert nach `snapshot_retention_days`, standardmäßig sieben Tagen.

| Muster | Einstellung | Ergebnis |
| --- | --- | --- |
| Zweite Kopie | `-a --delete --stats`, kurzes Intervall | Ausfallsicherheit; die Historie entspricht der des Zielservers |
| Zeitversetzte Kopie | `-a --delete --stats`, langes Intervall | eingefrorener Stand des letzten Laufs; Größe begrenzt sich selbst |
| Durchgehende Historie | `-a --delete --stats --filter='P backup_*/[0-9]*'` plus Aufbewahrung | lückenlose Historie über die eingestellten Tage |

**Zeitversetzt:** Läuft ein Spiegel nur alle 30 Tage, hält er bis zum nächsten Lauf den Bestand von damals – kurz vor dem nächsten Lauf also Stände, die auf dem Zielserver seit über drei Wochen rotiert sind. Das kostet nichts an Platz und verzögert außerdem Schaden: Wird der Bestand auf dem Zielserver verschlüsselt oder gelöscht, bleibt bis zum nächsten Lauf Zeit, das zu bemerken. Der Preis ist eine Lücke: Zwischen dem eingefrorenen Stand und dem aktuellen Fenster des Zielservers liegt ein Zeitraum, aus dem nirgends mehr etwas wiederherstellbar ist, und beim nächsten Lauf verschwinden die alten Stände auf einen Schlag.

**Durchgehend:** Die Schutzregel `P backup_*/[0-9]*` nimmt die Laufordner von der Löschung aus. Der Zielserver rotiert weiter, auf dem Spiegel bleiben die älteren Stände liegen, und `current`-Spiegel folgen der Quelle trotzdem exakt, weil sie nicht geschützt sind. Begrenzt wird der Spiegel dann durch seine eigene **Aufbewahrung**; ohne gesetzte Aufbewahrung wüchse er unbegrenzt. Dieses Muster ist das einzige, das jeden Tag innerhalb des Fensters abdeckt.

Filterregeln sind auf die auswertenden Typen begrenzt (`P`/`protect`, `+`/`include`, `-`/`exclude`, `H`, `S`, `R`); `merge` und `dir-merge` sind ausgeschlossen, weil sie eine Regeldatei von der Platte lesen würden.

Ein eigener Portal-Worker führt immer nur eine Replikation gleichzeitig aus. Zu Beginn jedes Laufs wird der freie Speicher des Ziels über `df` ermittelt und in der Oberfläche ausgewiesen. Status, Dauer, übertragenes Volumen und die vollständige rsync-Ausgabe stehen je Lauf zur Verfügung, ein Lauf lässt sich jederzeit manuell auslösen, und die Ergebnisse erscheinen zusätzlich im Aktivitätsfeed der Übersicht. rsync-Status 24 gilt als Erfolg: er bedeutet nur, dass während des Laufs eine Datei verschwunden ist, was auf einem aktiven Backupbestand regelmäßig vorkommt.

Wird ein Ziel im Portal entfernt, verschwinden Zugangsdaten, Zeitplan und Historie – die bereits replizierten Daten auf dem Spiegel bleiben liegen.

## Veränderung erkennen

Der Agent lässt jedes gestreamte Artefakt – Dateisystemarchive, Schemas, Datenbankdumps – auf dem Zielserver prüfsummieren, bevor es unter seinen endgültigen Namen wandert, und legt die Werte samt Gesamtfingerabdruck des Laufs in `manifest.json` ab. Das kostet einen warmen Lesevorgang auf dem Backupserver statt einer zweiten Übertragung, und ein Artefakt ohne gültige Prüfsumme wird gar nicht erst veröffentlicht.

Der Checker vergleicht deshalb zwei aufeinanderfolgende Läufe über ihre Fingerabdrücke und nicht mehr über die Byte-Größe. Gleich groß heißt nicht gleich: erst ein identischer SHA-256 belegt, dass sich am Inhalt nichts geändert hat. Das Volumen bleibt als Kennzahl erhalten.

Ein unveränderter Inhalt ist dabei kein Fehler. Die verglichene Größe stammt aus dem Quellvolumen, und das ist auf einem ruhigen Server zwischen zwei Läufen regelmäßig identisch – früher hat genau das reihenweise falsche Alarme erzeugt. Wer den Hinweis als Alarm behandeln möchte, aktiviert unter **Checker** die Option **Unveränderten Inhalt als Fehler werten**; sie greift ausschließlich bei zwei vorhandenen, identischen Prüfsummen. Läufe ohne Prüfsumme und Spiegelverzeichnisse lösen nie einen Alarm aus, sondern werden nur als solche ausgewiesen.

## Server aus dem Portal entfernen

Ein Server bleibt in der Übersicht, solange sein Linux-Zielkonto besteht – der Bestandsimport beim Portalstart würde einen gelöschten Eintrag ohnehin wieder anlegen. Wurde das Konto auf dem Zielserver entfernt, meldet die Übersicht **Systemkonto fehlt** und zählt den Eintrag unter **Konto fehlt**. Über **Entfernen** in der Zeile oder den Gefahrenbereich der Serverdetails lässt er sich dann dauerhaft löschen; entfernt werden Eintrag, Aufträge, Ereignisse, Laufprotokolle und Deployment-Tokens.

Das Home-Verzeichnis rührt RAVEN dabei nicht an. Sind dort noch Sicherungen abgelegt, weist das Portal darauf hin und die Daten bleiben liegen, bis sie bewusst entfernt werden.

## Benachrichtigungen

Ob eine Mail entsteht, entscheidet die Stelle, die sie auslöst. Empfänger sind in beiden Fällen die aktiven Portal-Benutzer mit hinterlegter Adresse und aktivierter Mailoption; ist SMTP abgeschaltet, versendet keine der beiden Seiten etwas.

Der Agent richtet sich nach der Policy des Servers. Dort lässt sich je Ereignis festlegen:

| Ereignis | Bedeutung | Standard |
| --- | --- | --- |
| Erfolgreiches Backup | Abschlussbericht mit Volumen, Dauer und Klassifizierungen | aktiv |
| Fehlgeschlagenes Backup | Phase, Fehlerklasse und Meldung des abgebrochenen Laufs | aktiv |
| Abgelehntes Backup | Der Agent hat einen Auftrag abgelehnt, weil das Intervall noch nicht abgelaufen war | aus |

Der zentrale Checker richtet sich nach den Einstellungen unter **Checker**:

| Ergebnis | Bedeutung | Standard |
| --- | --- | --- |
| Probleme | Alarm, sobald eine Prüfung von OK abweicht | aktiv |
| Wiederherstellung | Entwarnung, sobald ein gemeldetes Backup wieder aktuell ist | aktiv |
| Fehlerfreier Lauf | Vollständiger Bericht auch ohne Befund | aus |
| Erinnerungsabstand | Abstand, in dem ein weiterhin bestehendes Problem erneut gemeldet wird | 24 Stunden |
| Unveränderter Inhalt | Wertet zwei Läufe mit identischer Prüfsumme als Problem | aus |

Ein Force-Report versendet die Ergebnismail unabhängig von diesen Schaltern, ein Dry-Run versendet nie. Das Portal übergibt die Werte bei jedem Lauf; die Angaben in `backup-check.toml` greifen nur beim direkten Aufruf des Skripts.

### Updates und Wiederherstellung

Für ein Update zunächst den neuen Repository-Stand einspielen und `sudo bash install.sh` erneut ausführen. Das Skript ist idempotent, übernimmt vorhandene Einstellungswerte als Vorgaben, aktualisiert Python-Abhängigkeiten und startet den Dienst erst nach Konfiguration und Datenbankmigration neu.

Vorhandene Sicherungen werden nach folgendem Schema abgelegt:

- `/etc/backup-portal/config.toml.bak.<UTC-Zeitstempel>`
- `/etc/backup-portal/backup-check.toml.bak.<UTC-Zeitstempel>`
- `/var/lib/backup-portal/portal.db.bak.<UTC-Zeitstempel>`

Bei einem Fehler zuerst `journalctl -u backup-portal` und `/readyz` prüfen. Eine Datenbankwiederherstellung darf nur bei gestopptem Portal erfolgen. Dabei die aktuelle Datenbank zunächst separat sichern, anschließend das gewünschte Zeitstempel-Backup nach `portal.db` kopieren, Eigentümer `root:root` und Modus `0600` setzen und den Dienst wieder starten.
