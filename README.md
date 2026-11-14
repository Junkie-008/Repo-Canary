# Ransomware 207 — Repo-Canary

Canary-file ransomware detection for a Windows lab VM, now with a SQLite
store, automatic process attribution, local threat intelligence and PDF
incident reports.

The project watches a disposable folder, raises a **Critical** alert when a
canary file is touched, a **High** alert on mass file change, and a
**Confirmed Ransomware** alert when a touched file matches the local SHA-256
feed. A harmless simulator produces ransomware-like activity so the whole flow
can be demonstrated without any real malware.

Everything runs locally. The simulator only touches the marked lab folder, and
the test data is disposable.

---

## What is in the repository

| Path | Purpose |
|---|---|
| `scripts/detection_engine.py` | Watches the test folder with `watchdog`, persists findings, runs enrichment |
| `scripts/detection_rules.py` | Pure canary / mass-change / debounce / cooldown rules (no I/O) |
| `scripts/database.py` | SQLite schema, dedupe inserts, queries, migration, counters, heartbeat |
| `scripts/models.py` | Shared severity ranks, process details and `FindingRecord` |
| `scripts/attribution.py` | Sysmon Event ID 11 → `psutil` process attribution (or honest `none`) |
| `scripts/threat_intel.py` | Local SHA-256 feed loading and streaming file hashing |
| `scripts/reporting.py` | Throttled, asynchronous PDF incident reports |
| `scripts/logging_config.py` | Rotating `error_log.txt` + console logging |
| `scripts/dashboard_server.py` | Dashboard + paginated JSON API over `canary.db` |
| `index.html` | Live dashboard (Chart.js, heatmap, filters, pagination, CSV/JSONL) |
| `simulate_ransomware.py` | Controlled, harmless simulator with lab-marker guard |
| `scripts/reset_lab.py` | Restores canaries, disposable files and the lab marker |
| `scripts/negative_control_test.py` | FR-1.4 proof that ordinary activity stays silent |
| `scripts/process_attribution.py`, `scripts/correlation.py` | Manual PID → process lookup |
| `Sysmon/sysmonconfig.xml` | Sysmon config with Event ID 11 for the test folders |
| `Dockerfile`, `docker-compose.yml`, `docker/entrypoint.sh` | Cross-platform packaging |
| `vendor/chart.umd.min.js` | Vendored Chart.js (works offline) |
| `known_hashes.example.txt` | Threat-intel feed template |
| `tests/` | pytest suite for rules, database, intel, attribution, reporting, API |
| `AGENT.md` | Refactor decisions, progress and verification log |

---

## Requirements

- Windows (default paths are Windows paths; the code is portable)
- Python 3.12 or newer
- `watchdog`, `psutil`, `fpdf2` (see `requirements.txt`), plus pytest from
  `requirements-dev.txt`
- Optional: Sysmon 15 for automatic process attribution and independent
  Event ID 11 evidence
- Optional: Docker / Docker Compose for a Linux or WSL2 deployment

## Install

```bash
git clone https://github.com/Junkie-008/Repo-Canary.git
cd Repo-Canary

python -m venv .venv
source .venv/Scripts/activate      # Git Bash
# .venv\Scripts\activate           # cmd.exe

pip install -r requirements-dev.txt
```

## Quick start

Run each step in its own terminal, from the repository root.

```bash
# 1. Create/restore the disposable lab data (canaries + file1..file20)
python scripts/reset_lab.py --yes --clear-findings

# 2. Start the detection engine (watches C:\RansomwareLab\testdata)
python scripts/detection_engine.py

# 3. Start the dashboard, then open http://localhost:8000/index.html
python scripts/dashboard_server.py

# 4. In a third terminal, trigger the harmless simulation
python simulate_ransomware.py --yes
```

Expected result:

1. Three **CANARY ALERT** banners, one per canary file.
2. A **MASS-CHANGE ALERT** once 10 events land inside 10 seconds.
3. The dashboard shows the findings within about 2 seconds, with the
   events/minute chart and the latest detection card.
4. A PDF incident report is written to `C:\RansomwareLab\reports` for each
   alert (throttled to 12 per minute, and one per rule+path per minute).

`reset_lab.py` creates the lab folder and the `.repo-canary-lab` marker if they
do not exist, so this works on a machine that has never had
`C:\RansomwareLab`.

## Configuration

The default lab layout is the one used in the report:

```
C:\RansomwareLab\
├── testdata\          watched folder (canaries + disposable files)
├── monitored\         older simple-monitor folder
├── canary.db          SQLite findings, counters and engine heartbeat
├── reports\           PDF incident reports
├── known_hashes.txt   optional local SHA-256 threat-intel feed
├── error_log.txt      rotating log
└── scripts\           optional; scripts can run from the repo instead
```

Every path can be overridden with an environment variable or a command-line
flag.

| Environment variable | CLI flag | Default |
|---|---|---|
| `REPO_CANARY_LAB` | — | `C:\RansomwareLab` |
| `REPO_CANARY_TEST_DIR` | `--test-dir` | `<lab>\testdata` |
| `REPO_CANARY_MONITORED_DIR` | — | `<lab>\monitored` |
| `REPO_CANARY_DB` | `--db-path` | `<lab>\canary.db` |
| `REPO_CANARY_REPORTS` | `--report-dir` | `<lab>\reports` |
| `REPO_CANARY_HASHES` | `--hash-file` | `<lab>\known_hashes.txt` |
| `REPO_CANARY_LOG` | `--log-file` | `<lab>\error_log.txt` |
| `REPO_CANARY_FINDINGS` | `--findings` (deprecated) | `<lab>\findings.json` |

`--findings` is kept for old runbooks. It is interpreted as the legacy JSON
path; the database is placed beside it as `<name>.db`. Prefer `--db-path`.

Examples:

```bash
# Run entirely inside a scratch folder
python scripts/reset_lab.py --yes \
  --test-dir ./lab/testdata --db-path ./lab/canary.db
python scripts/detection_engine.py \
  --test-dir ./lab/testdata --db-path ./lab/canary.db
python scripts/dashboard_server.py --db-path ./lab/canary.db

# Or via the environment
export REPO_CANARY_LAB="$PWD/lab"
python scripts/detection_engine.py
```

### Legacy migration

On first start the engine imports `findings.json` (if present) into
`canary.db`, preserving every row with `source='json_migration'`, then renames
the file to `findings.json.migrated`. The migration runs once; the original is
never deleted.

---

## Detection rules

| Rule | Trigger | Severity | Finding summary |
|---|---|---|---|
| Canary | A canary file (`_canary_01.txt`, `_canary_02.txt`, `_canary_03.txt`) is created, modified, deleted or moved | Critical | `Canary file detected: <path>` |
| Mass change | 10 or more normalised events in a rolling 10-second window | High | `Mass-change detected: <n> events in 10 seconds` |
| Hash match | An alert-triggering file's SHA-256 is in the local feed | Confirmed Ransomware | `Canary file detected: <path>` (upgraded in place) |
| Debounce | Repeated events for the same path within 0.5 s | — | Collapsed; no extra finding |
| Cooldown | Another mass-change alert within 10 s of the last one | — | Suppressed |

Thresholds live at the top of `scripts/detection_rules.py`. Severity levels are
fixed by the rule that fires, and hash matches upgrade the row to
`Confirmed Ransomware` (rank 5, above Critical).

A rename now counts as **one** mass-change event: the source is counted and the
destination is still canary-checked.

### Process attribution

`watchdog` reports a path, not a PID, and `psutil` cannot attribute a write to
a process. The engine therefore correlates the file path and timestamp with
recent **Sysmon Event ID 11** records (via `wevtutil`), then enriches the PID
with `psutil`. A file is usually seen a few hundred milliseconds before Sysmon
has written the record, so a lookup re-reads the channel a couple of times
before giving up. If Sysmon is not installed, or the account cannot read the
channel, the finding records `attribution_method='none'` and no process — it
never guesses.

```bash
python scripts/detection_engine.py --attribution sysmon   # require Sysmon
python scripts/detection_engine.py --attribution none     # disable
```

## SQLite data model

`canary.db` uses WAL mode and contains:

- `findings` — one row per alert, with a unique `dedupe_key`, UTC timestamps,
  numeric `severity_rank`, file hash, intel label, report path and FK to
  `processes`
- `processes` — normalised process dimension reused across findings
- `known_hashes` — mirror of the local SHA-256 feed
- `event_counters` — buffered per-minute event volume for the chart
- `engine_state` — single-row heartbeat used by `/api/health`
- `schema_meta` — schema version and migration flags

Indexes cover `occurred_at`, `severity`, `rule`, `process_id`, `file_sha256`
and `severity_rank`.

## Dashboard

`index.html` is served by `scripts/dashboard_server.py` and refreshes every 2
seconds. It provides:

- total / confirmed / critical / high counters
- events-per-minute line chart and a process-activity heatmap (Chart.js,
  vendored so it works offline)
- latest-detection card
- server-side severity/rule/search filters and pagination
- CSV and JSONL export of the current filter
- pause, manual refresh, connection status, last update and an error banner
  that keeps the last good table on screen
- an "engine heartbeat missing" warning when the engine stops

API endpoints (read-only, JSON unless stated):

| Endpoint | Query |
|---|---|
| `/api/findings` | `severity`, `rule`, `q`, `since`, `until`, `limit`, `offset` |
| `/api/stats` | `hours` |
| `/api/events-per-minute` | `minutes` |
| `/api/top-processes` | `hours`, `limit` |
| `/api/process-heatmap` | `hours`, `top` |
| `/api/export` | `format=csv\|jsonl` + the findings filters |
| `/api/health` | — |
| `/findings.json` | legacy 50-row shape for old consumers |

Only `index.html` and `vendor/` are served; source files are not exposed.

## Docker

```bash
docker compose up --build
# dashboard: http://127.0.0.1:8000/index.html
```

The image is multi-stage, runs as a non-root user, and initialises
`/data/lab` on first start. The engine and dashboard share the
`canary-data` volume. Notes:

- On Windows, run the container against a Docker volume (as the compose file
  does) rather than a bind mount: inotify events from Windows paths may not
  propagate.
- The dashboard is bound to `127.0.0.1` on the host. It has no authentication;
  do not publish it.

## Verification

```bash
# 55 unit/integration tests: rules, SQLite, migration, intel, attribution,
# reporting, HTTP API and simulator guardrails
python -m pytest

# FR-1.4 negative control: ordinary activity must produce no alert
python scripts/negative_control_test.py
```

The negative-control script starts the real engine on a throw-away folder,
performs 3 creates, 1 append, 1 rename and 1 delete, and exits `0` only when
`canary.db` stayed empty. Use its console output as the evidence for FR-1.4
and the accuracy requirement (NFR 5.4).

## Sysmon evidence

`Sysmon/sysmonconfig.xml` includes FileCreate (Event ID 11) for both
`C:\RansomwareLab\testdata\` and `C:\RansomwareLab\monitored\`, as two separate
`FileCreate` rules (conditions inside one rule are AND-ed by Sysmon).

Apply it from an elevated prompt:

```bat
Sysmon64.exe -c C:\RansomwareLab\Sysmon\sysmonconfig.xml
```

With Sysmon installed, the engine performs attribution automatically. The
manual lookup remains available for validation:

```bash
python scripts/process_attribution.py <PID>
```

The full capture order, expected output and requirement mapping are in
[`EVIDENCE_CHECKLIST.md`](EVIDENCE_CHECKLIST.md).

## Known limitations

- Detection and response only: alerts are stored and reported. Automated
  containment, file recovery and host isolation are not implemented.
- Attribution needs Sysmon Event ID 11 *and* read access to
  `Microsoft-Windows-Sysmon/Operational`. A normal non-elevated account is
  denied that read, so either run the engine elevated or add the account to
  **Event Log Readers**; otherwise findings are unattributed by design.
- The threat-intel feed only matches known SHA-256 samples; it does not detect
  zero-day ransomware.
- The dashboard has no authentication or TLS; keep it on `127.0.0.1`.
- Tested on a single Windows VM; no long-duration false-positive measurement
  beyond the negative control.
- PDF reports are throttled and generated asynchronously; a burst intentionally
  coalesces duplicates for the same rule and path.
- The simulator is a controlled stand-in (it reverses text and renames files),
  not real ransomware, and refuses to run without the lab marker.
