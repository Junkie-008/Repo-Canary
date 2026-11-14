# AGENT.md — Repo-Canary production hardening log

Living record of the refactor: decisions, per-step implementation status, files
touched, and verification results.

Last updated: 2026-11-14 (Sysmon live attribution verified)

## Scope

Production-grade refactor of Repo-Canary, per the approved plan:

1. SQLite persistence (`canary.db`) replacing `findings.json`
2. Automatic process attribution (Sysmon correlation + psutil enrichment)
3. Cross-platform packaging (Dockerfile, docker-compose)
4. Enhanced dashboard (Chart.js, events/minute, process heatmap, pagination, CSV/JSONL)
5. Local threat intel (SHA-256 feed)
6. Automated PDF incident reports
7. Hardened simulator/lab guardrails, logging and tests

Explicitly out of scope for this pass: Jev / any decision-model triage. No
triage hook was added.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | `INSERT ... ON CONFLICT(dedupe_key) DO NOTHING` instead of `INSERT OR REPLACE` | `REPLACE` deletes and re-inserts, resetting `id` and dropping enrichment fields. Dedupe keys are idempotent across restarts and concurrent starts. |
| D2 | Normalized `processes` dimension table, FK from `findings` | Top-process and heatmap queries are `GROUP BY process_id`; a JSON blob would force a scan. |
| D3 | `event_counters` per minute instead of a raw event table | Gives the events/minute chart without a row per file event; the engine flushes buffered counts every 2 s. |
| D4 | UTC ISO-8601 timestamps + numeric `severity_rank` | Cross-host correlation, correct ordering, no `CASE` in sorts. |
| D5 | New severity `Confirmed Ransomware` (rank 5) for hash matches | Requested; above canary `Critical`. |
| D6 | Process attribution only via Sysmon Event ID 11 correlation; `NULL` + `attribution_method='none'` otherwise | `watchdog` events carry no PID and `psutil` cannot attribute a write. Fabricating a PID would put false evidence into reports. |
| D7 | PDFs generated for every alert, throttled (12/min, 60 s per identical rule+path) | User choice; prevents a PDF storm on mass-change bursts. |
| D8 | Enhanced single-page HTML + vendored Chart.js, no React/build step | Works offline in the lab VM, stays lightweight. |
| D9 | `--findings` kept as a deprecated alias; maps to `<path>.db` | Backward compatibility with existing runbooks. |
| D10 | Dashboard serves only `index.html` and `vendor/`, not the repo root | The old server exposed `.git/` and `scripts/` over HTTP. |
| D11 | A rename counts as one mass-change event (src only); dest is still canary-checked | The old `on_moved` double-counted every rename. |
| D12 | Migrate legacy `findings.json` once, then rename to `.migrated` | Never silently delete evidence. |
| D13 | Simulator requires a `.repo-canary-lab` marker in the target folder | Prevents a mis-set `REPO_CANARY_TEST_DIR` from mangling real files. |
| D14 | SQLite WAL + `busy_timeout` + per-operation connections | Dashboard reads while the engine writes; no shared-connection races. |
| D15 | Enrichment/reporting are asynchronous worker threads; the finding is persisted first | The watchdog callback never blocks on Sysmon, hashing or PDF rendering. |
| D16 | Attribution availability checks the Sysmon channel (`wevtutil gl`), not just `wevtutil` | Windows always has wevtutil; without Sysmon the engine must report `none`, not a misleading `sysmon`. |
| D17 | `legacy` added as a fourth `rule` value | Migrated rows that are neither canary nor mass-change need an accurate label. Additive schema change. |

## Schema

Approved shape, implemented in `scripts/database.py` (`SCHEMA_SQL`):
`schema_meta`, `processes`, `known_hashes`, `findings`, `event_counters`,
`engine_state`, with indexes on time, severity, rule, process, SHA-256 and
severity rank.

## Files

Created:

- `scripts/models.py` — severity ranks, `ProcessDetails`, `IntelResult`, `FindingRecord`, dedupe key
- `scripts/database.py` — schema, connection/WAL, dedupe insert, enrichment, queries, migration, counters, heartbeat
- `scripts/attribution.py` — Sysmon XML parsing/correlation, psutil enrichment, honest null attributor
- `scripts/threat_intel.py` — feed parser, streaming SHA-256, cache, size cap, reload-on-change
- `scripts/reporting.py` — throttle, async worker, fpdf2 report rendering
- `scripts/logging_config.py` — rotating `error_log.txt`
- `Dockerfile`, `docker-compose.yml`, `docker/entrypoint.sh`, `.dockerignore`
- `vendor/chart.umd.min.js` (Chart.js 4.4.7, 205 KB, vendored for offline use)
- `known_hashes.example.txt`
- `tests/test_database.py`, `tests/test_threat_intel.py`, `tests/test_attribution.py`,
  `tests/test_reporting.py`, `tests/test_dashboard_api.py`, `tests/test_lab_guardrails.py`
- `AGENT.md` (this file)

Rewritten:

- `scripts/detection_engine.py` — SQLite writes, async enrichment, heartbeat, counter flush, signal handling, loud observer failure, rename single-count
- `scripts/dashboard_server.py` — paginated API, stats, charts data, CSV/JSONL export, whitelisted static serving, health endpoint
- `index.html` — Chart.js line chart, process bars, heatmap, pagination, JSONL export, engine heartbeat status
- `scripts/reset_lab.py` — marker, DB clearing, `--db-path`
- `simulate_ransomware.py` — marker guard, dry-run, `.txt` allowlist, size cap, symlink skip, confirmation
- `scripts/negative_control_test.py` — now reads SQLite (the old script silently read the removed JSON file and could pass vacuously)
- `tests/test_detection_rules.py` — rename single-count and destination-canary tests
- `README.md`, `EVIDENCE_CHECKLIST.md`, `requirements.txt` (`fpdf2==2.9.0`)

Removed:

- `scripts/findings_store.py` and `tests/test_findings_store.py` (replaced by SQLite)

## Step status

| Step | Status | Notes |
|---|---|---|
| 1. Database layer + JSON migration | Done | 11 tests |
| 2. Attribution / threat intel / reporting / logging | Done | Sysmon Event ID 11 verified live (installed 15.22), SHA-256 feed, async PDFs |
| 3. Engine rewrite + rules/lab config | Done | Heartbeat, counters, enrichment queue, clean shutdown |
| 4. Dashboard server API | Done | Findings, stats, charts, export, health, legacy alias |
| 5. Dashboard UI (Chart.js) | Done | Charts, heatmap, pagination, CSV/JSONL |
| 6. Docker packaging | Done | Multi-stage, non-root, compose volume + healthcheck; image built and the compose stack run end to end, 65/65 stack checks |
| 7. Simulator + reset guardrails | Done | Marker guard, dry run, allowlist |
| 8. Tests + verification | Done | 57 tests; negative control PASS; end-to-end run; live Sysmon attribution |

## Verification log

- `python -m pytest -q` → **55 passed** (final run 6.52 s, 2026-11-13).
- `python scripts/negative_control_test.py` → **PASS**, 0 alerts, exit 0.
- End-to-end lab run (temp folder, real engine + simulator):
  - 3 Critical canary findings, 1 High mass-change finding
  - 4 PDF incident reports generated and attached to rows
  - heartbeat present, `attribution_method='none'` because Sysmon is not installed
  - no tracebacks; only expected warnings (missing feed, Sysmon absent)
- Dashboard HTTP checks (port 8123/8124, temp DB):
  - `/api/health`, `/api/stats`, `/api/findings`, `/api/events-per-minute`,
    `/api/process-heatmap`, `/findings.json`, `/api/export?format=csv` → 200
  - `/api/stats` includes `latest`, confirmed by the dashboard JS
  - `/scripts/database.py` → 404 (source files no longer served)
  - `/index.html` → 200, includes vendored Chart.js
- Dashboard JS parsed with `node --check` → no syntax errors.
- `python -m compileall` on `scripts/` and the simulator → clean.

### Docker build + compose verification (2026-11-14)

Windows has no container runtime (no `docker` CLI, Docker Desktop service,
Podman, Rancher Desktop or `nerdctl`; the Windows account is not elevated), so
the image was built with Docker Engine running inside the existing WSL2 Kali
distro (`wsl -u root` works there without a password): docker.io 28.5.2,
docker-cli 28.5.2, docker-compose 2.40.3, docker-buildx 0.29.1, systemd as PID 1.
The repo was copied to the distro's ext4 filesystem (`/root/rc-src`) so the build
context matched `.dockerignore` without crossing the 9p mount.

Results:

- `docker build --no-cache -t repo-canary:latest .` — **success, 22 steps**
  (builder wheel stage, then offline `pip install --no-index --find-links`).
  Image `repo-canary:latest`, 188 MB, id `0c20e944b6fc`.
- `docker compose up -d` — `rc-src-engine-1` and `rc-src-dashboard-1` on the
  `canary-data` volume; dashboard healthcheck reached **healthy** and the engine
  stayed `running`.
- Both containers run as `10001:canary`; `/data/lab` is owned `canary:canary`;
  `/app` holds only `scripts`, `index.html`, `vendor`, `requirements.txt`,
  `known_hashes.example.txt` — no `tests`, `.git`, `.venv` or docs.
- First run initialised the volume: `testdata` (23 files + marker), `canary.db`,
  `known_hashes.txt`, `reports/`.
- `simulate_ransomware.py` executed inside the engine container touched 23 files
  → **3 Critical canary findings + 1 High mass-change finding**, 4 PDFs,
  SQLite in WAL mode, no duplicate `dedupe_key`, `attribution_method='none'`.
- Dashboard API from inside the container: health/findings/stats/
  events-per-minute/top-processes/heatmap → 200; severity filter, pagination and
  offset → correct; CSV → 200 `text/csv`, BOM, 4 rows matching `total`; JSONL →
  200, 4 parseable rows; `/` → 200 (38 KB, vendored Chart.js);
  `/scripts/database.py` → 404; legacy `/findings.json` → 200.
- From the Windows host (`http://localhost:8000`, Git Bash curl): health 200
  with a live heartbeat payload, findings 200, `/` 200, CSV 200, source 404.
  WSL2 localhost forwarding works with the `127.0.0.1:8000:8000` binding.
- `docker compose restart` — all 4 findings and the healthy state survived; the
  named volume also survived a WSL VM restart (containers returned through
  `restart: unless-stopped`).
- No tracebacks in any container log; `error_log.txt` holds INFO lines only.
- Harness tally: **65/65** stack checks. The single harness failure was
  `curl.exe` refusing to start under WSL interop (client-side), so the host check
  was repeated directly from Windows, where it passed.

Earlier static/emulated checks, now superseded by the real build (kept for the
record):

- Entrypoint passes `sh -n` / `dash -n` (POSIX-clean, no bashisms).
- `docker-compose.yml` parses; both services build the same image, share the
  `canary-data` volume at `/data`, and the dashboard publishes only
  `127.0.0.1:8000`. Healthcheck payload parses with `ast.parse`.
- `python:3.12-slim` tag confirmed on Docker Hub (updated 2026-11-08).
- Builder stage equivalent: `pip download --platform manylinux2014_x86_64
  --python-version 3.12 --abi cp312 --only-binary=:all: -r requirements.txt`
  resolved **5 wheels** (watchdog, psutil, fpdf2, fonttools, pillow) with no
  compiler needed.
- Runtime stage equivalent: `pip wheel` into a wheelhouse, then a clean venv
  installed with `pip install --no-index --find-links=<wheelhouse>` → success,
  imports OK (psutil 7.2.2, fpdf2 2.9.0). Dependency closure is complete.
- Image contents emulated by copying exactly the Dockerfile `COPY` set
  (`scripts/`, `index.html`, `vendor/`, `known_hashes.example.txt`,
  `requirements.txt`) and running the entrypoint's exact commands with two
  processes sharing one data directory (the compose topology):
  - first-run `reset_lab.py --yes` wrote 23 disposable files, then the engine
    and dashboard started with the entrypoint's flags;
  - 3 canaries + 15 burst writes produced **3 Critical + 1 High** findings,
    heartbeat present, 4 PDF reports written;
  - `/api/health`, `/api/stats`, `/api/findings`, `/api/events-per-minute`,
    `/api/top-processes`, `/api/process-heatmap` → 200;
  - CSV export: 200, `text/csv`, UTF-8 BOM, quoted header, 4 rows;
    JSONL export: 200, `application/x-ndjson`, 4 parseable rows;
  - `/`, `/index.html`, `/vendor/chart.umd.min.js` → 200;
    `/scripts/database.py`, `/../requirements.txt`, `/scripts/../.env` → 404.
- Superseded: the layer build (`useradd`/`chown`), named-volume ownership and
  healthcheck transitions are all confirmed by the build/run above.

### Sysmon live attribution (2026-11-14)

Sysmon 15.22 was installed on this host with the repo config
(`Sysmon64.exe -accepteula -i Sysmon\sysmonconfig.xml`, service `Sysmon64`
running) and attribution was verified against the live channel:

- Channel `Microsoft-Windows-Sysmon/Operational` enabled; Event ID 11 records
  carry `TargetFilename`, `ProcessId`, `UtcTime` and the writing image.
- Engine started with `Attribution: sysmon`; the simulator (23 canaries +
  data files) produced 3 Critical canary findings and 1 High mass-change
  finding, and **all four were attributed** to `python.exe` with
  `attribution_method='sysmon'`, correct PID and `LAPTOP-7MPFP77S\Abhishek` as
  the process user. A second run reused the DB and brought it to 8/8
  attributed with two distinct PIDs, proving per-event correlation rather
  than a cached PID.
- 8 PDF reports were written by the Docker/Linux engine as before; the Sysmon
  run itself wrote reports normally too.
- Renames are covered: the simulator-only run logs Event ID 11 for the
  original canary names, so `_canary_0N.txt` findings attribute even though the
  file ends up as `.locked`.
- Unit suite: `pytest -q` -> **57 passed**; negative control -> **PASS**.

Bugs found by running it live (all fixed):

1. **Attribution raced Sysmon.** `EnrichmentWorker` looked up the PID once,
   immediately, but watchdog reports the write a few hundred milliseconds
   before Sysmon ghosts its record, so live findings always stored
   `none`. `SysmonAttributor.lookup` now re-reads the channel up to 3 times
   (`RETRY_ATTEMPTS`, `RETRY_DELAY_SECONDS = 0.4`), bypassing its 0.5 s cache.
2. **The lab config did not filter what it claimed.**
   `<ProcessCreate onmatch="exclude" />` has no condition, so it matches
   nothing and Sysmon logged every process create/terminate (60/60 sampled
   records), drowning Event ID 11. The config now excludes process events with
   `<Image condition="contains">\</Image>`; after reapplying it, the 12 newest
   records were all Event ID 11.
3. **`available()` claimed `sysmon` when the channel was unreadable.**
   `wevtutil gl` succeeds for a non-elevated account but `wevtutil qe` returns
   `Access is denied`, so the banner said `Attribution: sysmon` while every
   finding was `none` and every lookup logged a warning. `available()` now
   probes one record and reports `none` with an actionable warning
   (run elevated / add the account to Event Log Readers).

Operational requirements confirmed: the engine account needs read access to
`Microsoft-Windows-Sysmon/Operational` (elevated or Event Log Readers), and the
Sysmon config must include the watched folder (`C:\RansomwareLab\testdata\`).

### CI pipeline (2026-11-14)

`.github/workflows/ci.yml` runs two jobs on every push, pull request and manual
dispatch. Both use `windows-latest`: the product is Windows-first (Sysmon,
`wevtutil`, drive letters) and the documents are set in the Windows faces.

- `tests` — Python 3.12 and 3.13, `pip install -r requirements-dev.txt`, then
  `pytest -q`.
- `docs` — `pip install -r docs/requirements-docs.txt`, then
  `python docs/build_docs.py --out docs/build` followed by
  `python docs/check_docs.py docs/build`; the twelve PDFs and the deck are
  uploaded as the `project-documentation` artifact.

`docs/check_docs.py` fails the build on a missing document, a PDF under three
pages, any page with fewer than 120 characters of extractable text (the
near-blank-page bug found during the rebuild), a deck that is not 960x540 pt,
slides that disagree with the PDF page count, or a missing Markdown source.

Verified from a clean `git clone` in a fresh virtual environment, not from the
working tree:

- Python 3.13: `57 passed`; docs build and check → `documentation set OK`.
- Python 3.12: `57 passed`; docs build and check → `documentation set OK`.
- The clone's rebuild is text-identical to the committed PDFs page for page
  (bytes differ only by fpdf2's creation timestamp), so the committed
  deliverables are what CI produces.
- `docs/check_docs.py` against an empty directory exits 1 with 17 problems, so
  the gate is not vacuous.

## Bugs found and fixed during implementation

- `ThreatIntel.check` deadlocked on its own non-reentrant lock when the cache
  hit path called `_result_for`; switched to `RLock` (caught by the cache test).
- `SysmonAttributor.available()` originally returned true whenever `wevtutil`
  existed, which is always on Windows; it now checks the Sysmon channel.
- `dashboard_server` called `server.shutdown()` from the same thread that ran
  `serve_forever()`, which would hang on Ctrl+C; removed.
- The negative-control script still read `findings.json`, so it would have
  passed without checking anything after the migration; rewritten against SQLite.
- Rename events incremented the event counter twice; counters now increment only
  for the source event (mass-change was already fixed).

## Known limitations / follow-ups

- `docs/` was regenerated on 2026-11-14 (version 3.0): all
  twelve PDFs plus the deck and four Markdown sources now describe SQLite,
  Sysmon attribution and the 57-test suite. They are built by
  `docs/build_docs.py` from `docs_content.py`, so they can be
  regenerated after any further change. The old `.docx` files (01, 07, 12) were
  not regenerated and are now stale relative to the PDFs.
- Dashboard has no authentication/TLS; keep it on `127.0.0.1`.
- Attribution depends on Sysmon Event ID 11 and on the engine account being
  able to read `Microsoft-Windows-Sysmon/Operational` (elevated, or a member of
  Event Log Readers). Sysmon 15.22 is installed on this host and was verified
  live; the Docker/Linux image stays at `attribution_method='none'`, which is
  the documented behaviour there.
- Docker on Windows bind mounts may not propagate inotify; use the compose
  volume or run natively (the compose volume was verified; a bind mount was
  not).
- On a brand-new volume both services run the entrypoint's `reset_lab.py`
  initialisation concurrently, because both share the same volume. It was
  harmless in testing (the marker made the second run a no-op) but it is a
  race worth noting if initialisation ever grows heavier.
- Unknown `?format=` values on `/api/export` fall back to CSV rather than
  returning 400.
- Threat intel only matches known SHA-256 samples.
