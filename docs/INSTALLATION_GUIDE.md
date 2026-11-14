# Installation Guide

*Native Windows, Docker Compose and Sysmon setup with verification steps.*

## 1. Prerequisites

- Windows 10/11 or a Linux host; Python 3.12+ for a native run.
- Administrator access only for installing Sysmon and applying its configuration.
- Docker Engine or Docker Desktop for the container route.

## 2. Native installation

```
git clone https://github.com/Junkie-008/repo-canary
cd repo-canary
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Create the lab once, then start the two processes in separate terminals.

```
python scripts\reset_lab.py --yes
python scripts\detection_engine.py
python scripts\dashboard_server.py
```

## 3. Sysmon for attribution

Download Sysmon from Sysinternals, then install it with the repository configuration from an elevated prompt. The configuration logs FileCreate (Event ID 11) for the lab folders and excludes process events so the channel stays readable.

```
Sysmon64.exe -accepteula -i Sysmon\sysmonconfig.xml
Sysmon64.exe -c Sysmon\sysmonconfig.xml    # re-apply after editing
sc query Sysmon64
```

The engine account must be able to read Microsoft-Windows-Sysmon/Operational. Either run the engine elevated or add the account to the Event Log Readers group. When it cannot read the channel the engine says so and records attribution_method='none'.

## 4. Container installation

```
docker compose up -d --build
docker compose ps
docker compose logs -f engine
```

The compose file builds one image, runs the engine and the dashboard against the canary-data volume, and publishes the dashboard on 127.0.0.1:8000 with a healthcheck against /api/health. The entrypoint initialises the lab on first start.

## 5. Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| REPO_CANARY_LAB | C:\RansomwareLab | Lab root; all other paths default beneath it. |
| REPO_CANARY_TEST_DIR | <lab>\testdata | Folder the engine watches. |
| REPO_CANARY_MONITORED_DIR | <lab>\monitored | Folder used by the simple monitors. |
| REPO_CANARY_DB | <lab>\canary.db | SQLite database. |
| REPO_CANARY_FINDINGS | <lab>\findings.json | Legacy JSON, read once and migrated. |
| REPO_CANARY_REPORTS | <lab>\reports | PDF incident reports. |
| REPO_CANARY_HASHES | <lab>\known_hashes.txt | Local SHA-256 feed. |
| REPO_CANARY_LOG | <lab>\error_log.txt | Rotating engine log. |

## 6. Verification

```
python -m pytest -q                     # expect 57 passed
python scripts\negative_control_test.py # expect PASS, 0 alerts
curl http://127.0.0.1:8000/api/health    # expect ok:true, engine_alive:true
docker compose ps                         # expect dashboard (healthy)
```

## 7. Upgrading from the prototype

A findings.json beside the database is migrated automatically on first start and renamed to findings.json.migrated. The old --findings flag is still accepted as a deprecated alias and maps to a .db path, so existing shortcuts keep working while the runbooks are updated.
