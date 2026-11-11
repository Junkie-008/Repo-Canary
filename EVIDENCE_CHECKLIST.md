# Ransomware 207 — End-to-End Evidence Checklist

Use this checklist to produce the evidence for the report, the Day 4 support
pack (items M3–M7) and the viva demo. Every step lists what to run, what should
happen, and which requirement it proves.

Run everything in the isolated Windows lab VM, inside
`C:\RansomwareLab`, with disposable test data only.

---

## 0. Before the run

- [ ] VirtualBox snapshot `Clean-Before-Ransomware-Test` is available
- [ ] Sysmon 15 is installed and its service is running (`Sysmon64` / `Sysmon`)
- [ ] Python 3.12+ is installed and dependencies are present
      (`pip install -r requirements-dev.txt`)
- [ ] `C:\RansomwareLab` exists or the environment variables in
      `scripts/lab_config.py` point somewhere disposable
- [ ] `Sysmon/sysmonconfig.xml` has been applied (step 1)
- [ ] Create an `evidence\` folder for the screenshots; use the names below

The commands use `python`; substitute `py -3.12` if that is how Python is
invoked in the VM.

### 1. Apply the Sysmon configuration

The repository config now contains two FileCreate rules: one for
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
`Cleared ...\findings.json`. The folder now holds `_canary_01.txt` …
`_canary_03.txt` and `file1.txt` … `file20.txt`.

Capture: `evidence\02-lab-reset.png`.

Covers: FR-1.3 (known, disposable test data).

### 3. Run the automated tests

```bat
python -m pytest
```

Expected: all tests pass (`19 passed` with the current suite).

Capture: `evidence\03-pytest.png`.

Covers: verification of the canary, debounce, rate window, cooldown and
persistence rules.

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

Covers: FR-1.4, SRS §5.4 (accuracy), Day 4 item M7. This is the item that
was previously marked *not yet performed*; keep this screenshot as the
evidence that normal work does not trigger a false positive.

### 5. Start the detection engine

Terminal 1:

```bat
cd C:\RansomwareLab
python scripts\detection_engine.py
```

Expected header: `Watching: ...\testdata`, `Rate threshold: 10 events / 10
seconds`, `Canaries: _canary_01.txt, _canary_02.txt, _canary_03.txt`, then
`Status: WATCHING`.

Capture: `evidence\05-engine-started.png`.

Covers: FR-2.1 (watchdog monitoring is active).

### 6. Start the dashboard

Terminal 2:

```bat
cd C:\RansomwareLab
python scripts\dashboard_server.py
```

Open `http://localhost:8000/index.html`.

Expected: status shows **Connected • live monitoring**, counters are `0`, and
the table says no findings have been recorded.

Capture: `evidence\06-dashboard-idle.png`.

Covers: FR-3.2 (local HTTP access), FR-3.4 (connection status).

### 7. Run the controlled simulation

Terminal 3:

```bat
cd C:\RansomwareLab
python simulate_ransomware.py
```

Expected: `Attacking ONLY: ...\testdata`, then `touched _canary_01.txt`,
`touched _canary_02.txt`, `touched _canary_03.txt`, `touched file1.txt`, …,
`done`.

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
3. `WindowEvents=` counts increasing on the plain event lines.

Capture: `evidence\08-canary-alert.png` and
`evidence\09-mass-change-alert.png`.

Covers: FR-2.2, FR-2.3, UC-03.

### 9. Verify persistence and the dashboard

```bat
type C:\RansomwareLab\findings.json
```

Open the dashboard again (it refreshes every 3 seconds).

Expected:

- `findings.json` is a valid JSON list with `time`, `summary`, `severity`.
- Exactly three Critical entries, one per canary file.
- At least one High entry: `Mass-change detected: 10 events in 10 seconds`.
- The dashboard shows the same rows, the latest detection card, the filter
  counts, and a recent last-update time.

Capture: `evidence\10-findings-json.png`,
`evidence\11-dashboard-live.png`.

Covers: FR-3.1 (persistence + 50-entry cap), FR-3.3 (3-second refresh),
FR-3.4 (status/last update), UC-04.

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

### 11. Attribute the PID with psutil

```bat
cd C:\RansomwareLab
python scripts\process_attribution.py <ProcessId from step 10>
```

Expected: PID, name (`python.exe`), executable path, command line
(`simulate_ransomware.py`), username and status.

Capture: `evidence\13-process-attribution.png`.

Covers: FR-2.5, UC-05. If the simulator has already exited, run it again or
attribute the engine's PID (`detection_engine.py`) instead; note which one
you used in the run record below.

### 12. Record the run and clean up

- [ ] Stop the engine and dashboard with `CTRL+C`.
- [ ] Reset the lab data: `python scripts\reset_lab.py --yes --clear-findings`
- [ ] Restore the `Clean-Before-Ransomware-Test` snapshot.
- [ ] Fill in the run record below.
- [ ] Reference the evidence files in the SRS figures, the presentation and
      the Day 4 support pack.

---

## Expected results summary

| Check | Expected |
|---|---|
| Canary findings | 3 Critical, exactly one per canary file |
| Mass-change findings | At least 1 High: `Mass-change detected: 10 events in 10 seconds` |
| Duplicate canary rows | None (debounce runs before the canary rule) |
| Negative control | 0 alerts, exit code 0 |
| `findings.json` | Valid JSON list, newest last, at most 50 entries |
| Dashboard | Connected, rows visible within ~3 s, counters match the file |
| Sysmon | Event ID 11 with `ProcessId` and `TargetFilename` in `testdata` |
| Process attribution | PID resolves to `python.exe` / simulator command line |

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
| FR-2.5 psutil process attribution | 11 |
| FR-3.1 findings.json persistence | 9 |
| FR-3.2 local HTTP server | 6 |
| FR-3.3 dashboard refresh | 9 |
| FR-3.4 connection status / last update | 6, 9 |
| NFR 5.4 accuracy (negative control) | 4 |

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
| Sysmon version | |
| Engine PID | |
| Simulator PID (Sysmon `ProcessId`) | |
| Findings: Critical / High | |
| Negative control result (PASS/FAIL) | |
| pytest result | |
| Notes | |

---

## Troubleshooting

| Symptom | Check |
|---|---|
| Dashboard shows `Connection error` | Run `scripts/dashboard_server.py`, or serve `index.html` from the folder that contains `findings.json`; confirm the `--findings` path |
| No Sysmon Event ID 11 | Sysmon service running; config applied with `Sysmon64.exe -c`; the target path is exactly `C:\RansomwareLab\testdata\` (trailing backslash matters) |
| No canary alert | Engine is watching `testdata`, canary names are `_canary_01.txt` … `_canary_03.txt`, and `reset_lab.py` was run |
| Duplicate canary rows | You are running the old engine; use the current `scripts/detection_engine.py` (debounce runs first) |
| `UnicodeEncodeError` on print | Fixed in the current engine; run from the repository, not an old copy |
| Simulator does nothing | All files already end in `.locked`; run `reset_lab.py --yes` first |
| Findings path is wrong | Override with `--test-dir` / `--findings` or `REPO_CANARY_TEST_DIR` / `REPO_CANARY_FINDINGS` |
