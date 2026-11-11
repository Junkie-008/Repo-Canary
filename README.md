# Ransomware 207 — Repo-Canary

Canary-file ransomware detection for a Windows lab VM.

The project watches a disposable folder, raises a **Critical** alert when a
canary file is touched and a **High** alert on mass file change, stores the
findings in `findings.json`, and shows them on a live dashboard. A harmless
simulator produces ransomware-like activity so the whole flow can be
demonstrated without any real malware.

Everything runs locally. The simulator only touches the lab test folder, and
the test data is disposable.

---

## What is in the repository

| Path | Purpose |
|---|---|
| `scripts/detection_engine.py` | Watches the test folder with `watchdog` and raises alerts |
| `scripts/detection_rules.py` | Pure canary / mass-change / debounce / cooldown rules (no I/O) |
| `scripts/findings_store.py` | Atomic, 50-entry `findings.json` persistence |
| `scripts/dashboard_server.py` | Serves `index.html` and `/findings.json` on one origin |
| `index.html` | Live dashboard (search, severity filters, pause, CSV export) |
| `simulate_ransomware.py` | Controlled, harmless ransomware-like simulator |
| `scripts/reset_lab.py` | Restores canaries and disposable files before a demo |
| `scripts/negative_control_test.py` | FR-1.4 proof that ordinary activity stays silent |
| `scripts/process_attribution.py`, `scripts/correlation.py` | psutil PID → process details |
| `scripts/watchdog_monitor.py`, `scripts/activity_simulator.py` | Simple file-event monitor and older activity generator |
| `Sysmon/sysmonconfig.xml` | Sysmon config with Event ID 11 for the test folders |
| `EVIDENCE_CHECKLIST.md` | Step-by-step demo and evidence checklist mapped to the SRS |
| `tests/` | pytest suite for the detection rules and findings store |

---

## Requirements

- Windows (the default paths are Windows paths; the code itself is portable)
- Python 3.12 or newer
- `watchdog` and `psutil` (see `requirements.txt`), from `requirements-dev.txt` for pytest
- Optional: Sysmon 15 for independent Event ID 11 evidence
- Optional: VirtualBox for the isolated lab VM described in the report

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
python simulate_ransomware.py
```

Expected result:

1. A **CANARY ALERT** (Critical) for `_canary_01.txt` before anything else.
2. A **MASS-CHANGE ALERT** (High) once 10 events land inside 10 seconds.
3. The dashboard shows both rows within about 3 seconds of the next poll.
4. Each file operation is recorded **once** per canary file — the debounce
   now runs before the canary rule, so duplicate findings are gone.

`reset_lab.py` creates the lab folder if it does not exist, so this works on a
machine that has never had `C:\RansomwareLab`.

---

## Configuration

The default lab layout is the one used in the report:

```
C:\RansomwareLab\
├── testdata\          watched folder (canaries + disposable files)
├── monitored\         older simple-monitor folder
├── findings.json      alert history (latest 50)
└── scripts\           optional; scripts can run from the repo instead
```

Every path can be overridden with an environment variable or a command-line
flag, so the project also runs from a checkout, a test run, or another PC.

| Environment variable | CLI flag | Default |
|---|---|---|
| `REPO_CANARY_LAB` | — | `C:\RansomwareLab` |
| `REPO_CANARY_TEST_DIR` | `--test-dir` | `<lab>\testdata` |
| `REPO_CANARY_MONITORED_DIR` | — | `<lab>\monitored` |
| `REPO_CANARY_FINDINGS` | `--findings` | `<lab>\findings.json` |

Examples:

```bash
# Run entirely inside a scratch folder
python scripts/reset_lab.py --yes --test-dir ./lab/testdata --findings ./lab/findings.json
python scripts/detection_engine.py --test-dir ./lab/testdata --findings ./lab/findings.json
python scripts/dashboard_server.py --findings ./lab/findings.json

# Or via the environment
export REPO_CANARY_LAB="$PWD/lab"
python scripts/detection_engine.py
```

The simulator reads `REPO_CANARY_TEST_DIR`, so it follows the same override.

---

## Detection rules

| Rule | Trigger | Severity | Finding summary |
|---|---|---|---|
| Canary | A canary file (`_canary_01.txt`, `_canary_02.txt`, `_canary_03.txt`) is created, modified, deleted or moved | Critical | `Canary file detected: <path>` |
| Mass change | 10 or more normalised events in a rolling 10-second window | High | `Mass-change detected: <n> events in 10 seconds` |
| Debounce | Repeated events for the same path within 0.5 s | — | Collapsed; no extra finding |
| Cooldown | Another mass-change alert within 10 s of the last one | — | Suppressed |

Thresholds live at the top of `scripts/detection_rules.py`. Severity levels are
fixed by the rule that fires (canary = Critical, mass change = High), matching
the SRS.

### `findings.json`

A JSON list, newest last, capped at 50 entries:

```json
[
  {
    "time": "2026-11-11 14:03:27",
    "summary": "Canary file detected: C:\\RansomwareLab\\testdata\\_canary_01.txt",
    "severity": "Critical"
  }
]
```

Writes are atomic (temporary file + `os.replace`), so the dashboard can poll
while the engine writes and never reads a truncated file.

---

## Dashboard

`index.html` polls `findings.json` every 3 seconds and provides:

- total / Critical / High / other counters
- a latest-detection card
- severity filter chips and free-text search
- pause and manual refresh
- CSV export of the currently filtered view
- a connection status, last update time, and a banner on fetch errors —
  the last good table stays visible instead of being replaced by an error

Serve it with `scripts/dashboard_server.py` (recommended), or copy
`index.html` next to `findings.json` and start `python -m http.server 8000`
from the lab folder as described in the report.

---

## Verification

```bash
# Unit tests for the rules and persistence (no lab folder needed)
python -m pytest

# FR-1.4 negative control: ordinary activity must produce no alert
python scripts/negative_control_test.py
```

The negative-control script starts the real engine on a throw-away folder,
performs 3 creates, 1 append, 1 rename and 1 delete, and exits `0` only when
`findings.json` stayed empty. Use its console output as the evidence for
SRS §5.4 / FR-1.4 and the Day 4 support pack item M7.

---

## Sysmon evidence

`Sysmon/sysmonconfig.xml` includes FileCreate (Event ID 11) for both
`C:\RansomwareLab\testdata\` and `C:\RansomwareLab\monitored\`, as two separate
`FileCreate` rules (conditions inside one rule are AND-ed by Sysmon).

Apply it from an elevated prompt, then verify Event ID 11 in Event Viewer:

```bat
Sysmon64.exe -c C:\RansomwareLab\Sysmon\sysmonconfig.xml
```

Event ID 11 shows which `ProcessId` touched a file, which you can feed to:

```bash
python scripts/process_attribution.py <PID>
```

Matching Sysmon's PID to an alert is still a manual evidence step; the PID is
not stored in `findings.json`. The full capture order, expected output and
requirement mapping are in [`EVIDENCE_CHECKLIST.md`](EVIDENCE_CHECKLIST.md).

---

## Known limitations

- Detection and response only: alerts are printed, persisted and displayed.
  Automated containment or file recovery is not implemented (future scope).
- Tested in a single Windows VM; no long-duration or false-positive rate
  measurement beyond the negative-control run.
- `findings.json` is a JSON file, not a database; only the latest 50 findings
  are kept.
- The simulator is a controlled stand-in (it reverses text and renames files),
  not real ransomware.
- Windows is the assumed platform; the canary filenames and default paths are
  fixed in `scripts/detection_rules.py` and `scripts/lab_config.py`.
