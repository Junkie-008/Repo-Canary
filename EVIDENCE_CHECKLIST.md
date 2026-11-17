# Ransomware 207 — End-to-End Evidence Checklist

Use this checklist to produce the evidence for the eight project PDFs
(architecture, diagrams, database, testing, user manual, future scope, synopsis
and presentation) and the viva demo. Every step lists what to run, what should
happen, and which requirement it proves.

Run everything in the isolated Windows lab VM, inside
`C:\RansomwareLab`, with disposable test data only.

---

## 0. Before the run

- [ ] VirtualBox snapshot `Clean-Before-Ransomware-Test` is available
- [ ] Sysmon 15 is installed and its service is running (`Sysmon64` / `Sysmon`)
      — required for automatic process attribution
- [ ] Python 3.12+ is installed and dependencies are present
      (`pip install -r requirements-dev.txt`)
- [ ] `C:\RansomwareLab` exists or the environment variables in
      `scripts/lab_config.py` point somewhere disposable
- [ ] `Sysmon/sysmonconfig.xml` has been applied (step 1)
- [ ] Create an `evidence\` folder for the screenshots; use the names below

The commands use `python`; substitute `py -3.12` if that is how Python is
invoked in the VM.

### 1. Apply the Sysmon configuration

The repository config contains two FileCreate rules: one for
`C:\RansomwareLab\monitored\` and one for `C:\RansomwareLab\testdata\`.
Conditions inside a single rule are AND-ed, so the two folders must be
separate `FileCreate` elements.

```bat
cd C:\RansomwareLab
Sysmon64.exe -c C:\RansomwareLab\Sysmon\sysmonconfig.xml
```

If the VM keeps the config at `C:\Sysmon\sysmonconfig.xml` (as the SRS
mentions), copy this repository's file there first and apply that path.

Expected: `Configuration file validated.` and `Configuration updated.`
Then check that Event Viewer receives events:

1. Open **Event Viewer → Applications and Services Logs → Microsoft →
   Windows → Sysmon → Operational**.
2. **Filter Current Log… → Event ID 11**.
3. Touch a file in `C:\RansomwareLab\testdata` (a new empty test file is
   enough) and confirm a new `FileCreate` event appears with
   `TargetFilename` under `testdata`.

Capture: `evidence\01-sysmon-config-applied.png` (service status and/or
validated configuration output).

Covers: FR-2.4.

### 2. Restore the lab data and clear old findings

```bat
cd C:\RansomwareLab
python scripts\reset_lab.py --yes --clear-findings
```

Expected: `Removed N .locked file(s)`, `Wrote 23 disposable file(s)`,
`Cleared findings in C:\RansomwareLab\canary.db`. The folder now holds
`_canary_01.txt` … `_canary_03.txt`, `file1.txt` … `file20.txt`, and the
`.repo-canary-lab` marker required by the simulator.

Capture: `evidence\02-lab-reset.png`.

Covers: FR-1.3 (known, disposable test data).

### 3. Run the automated tests

```bat
python -m pytest
```

Expected: all tests pass (`67 passed` with the current suite).

Capture: `evidence\03-pytest.png`.

Covers: verification of the canary, debounce, rate window, cooldown, SQLite
persistence, canary baseline and integrity scans, migration, threat intel,
attribution parsing, PDF reporting, HTTP API and simulator guardrails.

### 4. Negative control — ordinary activity must stay silent (FR-1.4)

```bat
python scripts\negative_control_test.py
```

Expected:

```
Alerts:     0
[PASS] Normal activity produced no alert (no false positive).
```

Capture: `evidence\04-negative-control.png`.

Covers: FR-1.4 and the accuracy requirement (NFR 5.4). Keep this screenshot as
the evidence that normal work does not trigger a false positive.

### 5. Start the detection engine

Terminal 1:

```bat
cd C:\RansomwareLab
python scripts\detection_engine.py
```

Expected header: `Watching: ...\testdata`, `Database: ...\canary.db`,
`Attribution: sysmon`, `Threshold: 10 events / 10 s`, `Canaries:
_canary_01.txt, _canary_02.txt, _canary_03.txt`, `Baseline: 3 stored;
startup scan 0 problem(s)`, `Integrity: every 300s`, then `Status: WATCHING`.

Capture: `evidence\05-engine-started.png`.

Covers: FR-2.1 (watchdog monitoring is active), FR-2.5 (attribution source).

### 6. Start the dashboard

Terminal 2:

```bat
cd C:\RansomwareLab
python scripts\dashboard_server.py
```

Open `http://localhost:8000/index.html`.

Expected: status shows **Connected • engine live**, counters are `0`, the
table says no findings match yet, and the events chart is empty.

Capture: `evidence\06-dashboard-idle.png`.

Covers: FR-3.2 (local HTTP access), FR-3.4 (connection status).

### 7. Run the controlled simulation

Terminal 3:

```bat
cd C:\RansomwareLab
python simulate_ransomware.py --yes
```

Expected: `Attacking ONLY: ...\testdata`, then `touched _canary_01.txt`,
`touched _canary_02.txt`, `touched _canary_03.txt`, `touched file1.txt`, …,
`done (23 file(s))`.

Capture: `evidence\07-simulator-run.png`.

Covers: FR-1.1, FR-1.2, FR-1.3, UC-02.

### 8. Capture the terminal alerts

Look at Terminal 1.

Expected, in this order:

1. Three **CANARY ALERT** blocks, one each for `_canary_01.txt`,
   `_canary_02.txt`, `_canary_03.txt` — **one finding per canary file**, not
   two or three.
2. One or more **MASS-CHANGE ALERT** blocks once 10 events fall inside the
   rolling 10-second window.
3. Per-event lines are now debug-level log entries; set
   `REPO_CANARY_LOG`/`--log-file` and inspect `error_log.txt` if you need them.

Capture: `evidence\08-canary-alert.png` and
`evidence\09-mass-change-alert.png`.

Covers: FR-2.2, FR-2.3, UC-03.

### 9. Verify persistence, reports and the dashboard

```bat
python -c "import sys; sys.path.insert(0,'scripts'); from pathlib import Path; from database import FindingsDB; db=FindingsDB(Path(r'C:\RansomwareLab\canary.db')); rows=db.list_findings(limit=50); print(len(rows), 'findings'); [print(r['occurred_at'], r['severity'], r['rule'], r['summary']) for r in rows]"
dir C:\RansomwareLab\reports
```

Expected:

- Four or more rows in `canary.db`: exactly three `Critical` canary findings
  plus at least one `High` mass-change finding.
- Each row has a UTC timestamp, a rule, and a report path.
- `reports\` contains one PDF per alert (subject to the 12/minute throttle).
- The dashboard shows the same rows, the charts, the latest detection card,
  the filter counts, and a recent last-update time.
- **Findings are not capped at 50** any more; the table paginates 25 rows at a
  time and the API accepts `offset`.

Capture: `evidence\10-database.png`, `evidence\11-dashboard-live.png`.

Covers: FR-3.1 (SQLite persistence), FR-3.3 (2-second refresh),
FR-3.4 (status/last update), UC-04.

### 9a. Optional — prove restart integrity continuity

Stop the engine, change a canary while it is down, then restart it with the
startup scan enabled. This proves that a change made during downtime is not
lost, and that the scan finding is not duplicated by watchdog.

```bat
REM 1. Stop the engine with CTRL+C, then tamper with a canary while it is down
echo tampered > C:\RansomwareLab\testdata\_canary_01.txt

REM 2. Restart the engine (the startup scan runs before watchdog)
python scripts\detection_engine.py --attribution none --no-reports --integrity-interval 5
```

Expected: `Baseline: 3 stored; startup scan 1 problem(s)` and a Critical
`Canary file modified during the startup integrity scan` finding. Query the
new row:

```bat
python -c "import sys; sys.path.insert(0,'scripts'); from pathlib import Path; from database import FindingsDB; db=FindingsDB(Path(r'C:\RansomwareLab\canary.db')); rows=db.list_findings(limit=50); print([(r['severity'], r['rule'], r['event_type'], r['summary']) for r in rows if r['event_type'] in ('startup_scan','integrity_scan')])"
```

Expected: exactly one row with `event_type='startup_scan'`; periodic scans do
not add a duplicate. Stop the engine and run
`python scripts\reset_lab.py --yes --clear-findings` afterwards.

Capture: `evidence\15-restart-integrity.png`.

Covers: FR-9.1 / FR-9.2 (restart continuity and duplicate suppression).

### 10. Capture the Sysmon Event ID 11 evidence

In Event Viewer → Sysmon → Operational, filter **Event ID 11** and find the
events whose `TargetFilename` is under `C:\RansomwareLab\testdata\`.

The event shows:

- `Event ID: 11` (FileCreate)
- `Image: ...\python.exe`
- `TargetFilename: C:\RansomwareLab\testdata\_canary_01.txt` (and the other
  test files)
- `ProcessId` — the simulator's PID for this run

Capture: `evidence\12-sysmon-event11.png` (open the event's **Details** tab so
`ProcessId` and `TargetFilename` are visible).

Covers: FR-2.4, UC-05. Record the PID for the next step.

### 11. Confirm process attribution

Open the dashboard row for a canary finding. Expected: the Process column
shows `python.exe` (or the simulator's image), the PID, and a truncated
command line, because the engine correlated Sysmon Event ID 11 automatically
(`attribution_method='sysmon'`).

The manual lookup is still available for cross-checking:

```bat
cd C:\RansomwareLab
python scripts\process_attribution.py <ProcessId from step 10>
```

Expected: PID, name (`python.exe`), executable path, command line
(`simulate_ransomware.py`), username and status.

Capture: `evidence\13-process-attribution.png`.

Covers: FR-2.5, UC-05. If the simulator has already exited, the engine records
`attribution_method='none'` and no process rather than guessing.

### 12. Open a PDF incident report

Open one of the files in `C:\RansomwareLab\reports`.

Expected: an `INC-00000N-...pdf` containing the report ID, UTC detection
time, severity, rule, summary, file path, SHA-256, process attribution and
engine version.

Capture: `evidence\14-incident-report.png`.

Covers: the reporting/response extension of FR-3.

### 13. Record the run and clean up

- [ ] Stop the engine and dashboard with `CTRL+C`.
- [ ] Reset the lab data: `python scripts\reset_lab.py --yes --clear-findings`
- [ ] Restore the `Clean-Before-Ransomware-Test` snapshot.
- [ ] Fill in the run record below.
- [ ] Reference the evidence files in the testing report, synopsis and presentation.

---

## Expected results summary

| Check | Expected |
|---|---|
| Canary findings | 3 Critical, exactly one per canary file |
| Mass-change findings | At least 1 High: `Mass-change detected: 10 events in 10 seconds` |
| Duplicate canary rows | None (debounce runs before the canary rule) |
| Negative control | 0 alerts, exit code 0 |
| `canary.db` | Three Critical + at least one High, UTC timestamps, unique dedupe keys |
| PDF reports | One per alert in `reports\`, throttled to 12/minute |
| Dashboard | Connected, rows within ~2 s, charts and heartbeat status visible |
| Sysmon | Event ID 11 with `ProcessId` and `TargetFilename` in `testdata` |
| Process attribution | Automatic via Sysmon; `none` (never a guess) when unavailable |
| Restart integrity | A canary changed while stopped produces exactly one Critical `startup_scan` finding; no periodic duplicate |

> The mass-change summary reports the number of events in the window at the
> moment the alert fires; the first alert is always `10 events`.

## Requirement coverage

| Requirement | Evidence step |
|---|---|
| FR-1.1 / FR-1.2 controlled simulation | 7 |
| FR-1.3 disposable data and canaries | 2, 7 |
| FR-1.4 negative control (no false positive) | 4 |
| FR-2.1 watchdog file events + debounce | 5, 8 |
| FR-2.2 canary alert | 8, 9 |
| FR-2.3 mass-change alert + cooldown | 8, 9 |
| FR-2.4 Sysmon Event ID 11 | 1, 10 |
| FR-2.5 process attribution | 11 |
| FR-3.1 SQLite persistence | 9 |
| FR-3.2 local HTTP server | 6 |
| FR-3.3 dashboard refresh | 9 |
| FR-3.4 connection status / last update | 6, 9 |
| NFR 5.4 accuracy (negative control) | 4 |
| FR-9.1 / FR-9.2 canary integrity and restart continuity | 9a |

---

## Run record

Fill this in for the demo run that produced the screenshots.

| Field | Value |
|---|---|
| Date and time | |
| VM / snapshot | |
| Python version | |
| watchdog version | |
| psutil version | |
| fpdf2 version | |
| Sysmon version | |
| Engine PID | |
| Simulator PID (Sysmon `ProcessId`) | |
| Findings: Confirmed / Critical / High | |
| PDF reports generated | |
| Negative control result (PASS/FAIL) | |
| Startup scan result (0 problems / 1 problem) | |
| pytest result | |
| Notes | |

---

## Troubleshooting

| Symptom | Check |
|---|---|
| Dashboard shows `Connection error` | Run `scripts/dashboard_server.py` and pass the same `--db-path` the engine uses; confirm `canary.db` is readable |
| `engine heartbeat missing` | The engine is stopped or crashed; check `error_log.txt` and restart it |
| No Sysmon Event ID 11 | Sysmon service running; config applied with `Sysmon64.exe -c`; the target path is exactly `C:\RansomwareLab\testdata\` (trailing backslash matters) |
| Process column says `unattributed` | Sysmon is not installed or the channel is unreadable; run the engine with `--attribution sysmon` and check `error_log.txt` |
| No canary alert | Engine is watching `testdata`, canary names are `_canary_01.txt` … `_canary_03.txt`, and `reset_lab.py` was run |
| Duplicate canary rows | Check for a second engine instance writing to the same DB; dedupe keys make the same event idempotent, not repeated events |
| Startup scan reports a missing canary | The lab was not reset, or a canary changed while the engine was stopped; run `reset_lab.py --yes` to restore the baseline |
| No PDF report | `--no-reports` set, fpdf2 missing, or the throttle coalesced duplicates for the same rule+path |
| Simulator refuses to run | The target folder lacks the `.repo-canary-lab` marker; run `reset_lab.py --yes` |
| Findings path is wrong | Override with `--db-path` or `REPO_CANARY_DB`; `--findings` is deprecated and maps to `<name>.db` |
