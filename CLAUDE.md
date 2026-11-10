# RAVEN – Arbeitsregeln für Claude

## Nach jeder Änderung: committen, pushen, deployen

Jede Code-Änderung wird sofort **committet, auf `origin/master` gepusht und auf Produktion deployt**.
Nicht auf eine Nachfrage warten, nicht am Ende sammeln.

1. Tests laufen lassen (siehe unten).
2. `git commit` mit sinnvoller englischer Nachricht (Stil: kurze Imperativ-Zeile, Begründung im Body).
3. `git push origin master`.
4. Deployen (siehe „Zugang zur Produktion").

`deploy/deploy.sh` bricht ab, wenn das Arbeitsverzeichnis nicht sauber ist oder HEAD nicht auf
`origin/master` liegt. Liegen fremde, uncommittete Änderungen herum: nicht mitcommitten und nicht
verwerfen, sondern melden, dass das Deployen daran scheitert.

## Zugang zur Produktion

Hier stehen nur **Fundorte**, keine Zugangsdaten. Die Schlüssel liegen außerhalb des Repos in OneDrive.

- Produktion: `root@backup-prd.pulseone.cloud`, SSH-Port `49150`, nur Key-Login.
- SSH-Key: `C:\Users\cp\OneDrive\SSH Keys\hosthatch_backup-prd\id_rsa`
  (das `.ppk` daneben nutzt die WinSCP-Session in `C:\Users\cp\OneDrive\Dokumente\WinSCP.ini`).
- Weitere Hosts: Quellserver dev1 `srv-dev1.pulseone.cloud:49150` mit Key unter
  `...\SSH Keys\hosthatch_dev1-pulseone-cloud\`, Mirror-Boxen unter `...\SSH Keys\BackupBoxen_PulseMedia\backupbox1|2`.
- Deployen aus der Git-Bash, auf sauberem, gepushtem `master`:

  ```bash
  RAVEN_SSH_TARGET=root@backup-prd.pulseone.cloud \
  RAVEN_SSH_KEY="/c/Users/cp/OneDrive/SSH Keys/hosthatch_backup-prd/id_rsa" \
  bash deploy/deploy.sh
  ```

  Das Script verweigert den Lauf, solange Backup-, Cleanup- oder Mirror-Läufe aktiv sind, legt
  Snapshot und `portal.db.pre-<sha>` an, prüft `/readyz` und rollt bei Fehler zurück.
- Auf dem Server gibt es kein `sqlite3`-CLI; Abfragen über `/opt/raven/venv/bin/python`.
- Mirror-Box `backupbox1` verträgt rsync nur mit `--bwlimit=8M`.

## Tests

`fastapi` und `pwd` fehlen unter Windows. Die Suite läuft in WSL mit dem vorhandenen venv:

```bash
wsl -d Debian -- bash -lc 'cd /mnt/c/Users/cp/PycharmProjects/RAVEN && ~/raven-venv/bin/python -m unittest discover -s tests'
```

CI (`.github/workflows`) führt dasselbe plus `bash -n` auf den Shell-Skripten aus.
