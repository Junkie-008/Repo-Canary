# README

*Project overview, quick start and repository map.*

## Ransomware 207 - Repo-Canary

Incident detection for a ransomware attack on a Windows server. The engine watches a disposable lab folder, detects canary tampering and mass file change, attributes the writing process through Sysmon Event ID 11, enriches affected files with SHA-256 threat intelligence, writes a PDF incident report per alert and exposes everything through a local dashboard.

## Highlights

- SQLite evidence store with WAL, unique dedupe keys and one-time JSON migration.
- Honest attribution: Sysmon correlation when available, 'none' when it is not.
- Asynchronous enrichment and PDF reporting, so the watchdog thread never blocks.
- Paginated JSON API with CSV and JSONL export, feeding a Chart.js dashboard.
- Multi-stage Docker image, non-root user, shared volume, healthcheck.
- 57 automated tests, a negative control and recorded end-to-end evidence.

## Quick start

```
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
python scripts\reset_lab.py --yes
python scripts\detection_engine.py
# second terminal
python scripts\dashboard_server.py
```

## Repository map

| Path | Contents |
| --- | --- |
| scripts/detection_engine.py | Engine: observer, rules, persistence, enrichment, heartbeat. |
| scripts/detection_rules.py | Canary and mass-change rules. |
| scripts/database.py | SQLite schema, queries, migration. |
| scripts/attribution.py | Sysmon Event ID 11 correlation and psutil enrichment. |
| scripts/threat_intel.py | Local SHA-256 feed with cache and reload. |
| scripts/reporting.py | PDF incident reports and throttle. |
| scripts/dashboard_server.py | Read-only HTTP API and static dashboard. |
| index.html | Dashboard UI (vendored Chart.js). |
| simulate_ransomware.py | Harmless drill inside a marked lab. |
| Sysmon/sysmonconfig.xml | Sysmon configuration for the lab folders. |
| tests/ | 57 tests across seven modules. |
| Dockerfile, docker-compose.yml | Container packaging. |

## Evidence in one place

- Findings live in canary.db; reports are PDFs under reports/.
- The dashboard is the fastest way to read them; the API is the scriptable way.
- AGENT.md records the design decisions and the verification log.

## Limitations

Detection and evidence only: no containment or recovery. The dashboard has no authentication and binds to loopback. Threat intelligence matches known hashes only. Attribution requires Sysmon and read access to its channel.
