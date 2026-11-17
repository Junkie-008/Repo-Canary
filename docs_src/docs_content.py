"""Content for the Ransomware 207 documentation set.

Every document is defined once as a list of blocks and rendered to PDF (and,
where useful, Markdown) by ``docs_builder``. Facts below are taken from the
current Repo-Canary tree: SQLite storage, Sysmon Event ID 11 attribution,
persisted canary integrity scans, fpdf2 incident reports, the Docker packaging
and the 67-test suite.
"""

from __future__ import annotations

from pathlib import Path

from docs_builder import Document

VERSION = "2.0.0"
IMAGES = Path(__file__).resolve().parent / "images"

SCHEMA_ROWS = [
    ["schema_meta", "key TEXT PK, value TEXT", "Key/value metadata; schema_version records the schema revision and the migration flag prevents a second import."],
    ["processes", "id, name, exe_path, cmdline, username, first_seen, last_seen", "Normalised process dimension shared by findings; UNIQUE(name, exe_path, cmdline)."],
    ["known_hashes", "sha256 PK CHECK(length=64), label, source, added_at", "Mirror of the local SHA-256 threat-intel feed."],
    ["canary_baseline", "name PK, sha256 CHECK(length=64), size, mtime_ns, captured_at", "Expected canary content, size and timestamp used by startup and periodic integrity scans."],
    ["findings", "id, occurred_at, severity, severity_rank, rule, trigger_rule, summary, path, event_type, process_id, pid, attribution_method, file_sha256, intel_label, matched_hash, report_path, report_created_at, source, dedupe_key, created_at", "One row per alert. CHECK constraints on severity, rule, attribution_method and source; UNIQUE(dedupe_key)."],
    ["event_counters", "minute, event_type, count", "Buffered per-minute event volume for the dashboard chart; PRIMARY KEY(minute, event_type)."],
    ["engine_state", "id CHECK(id=1), started_at, last_heartbeat, watch_dir, version", "Single-row heartbeat read by /api/health and the dashboard."],
]

INDEX_ROWS = [
    ["idx_findings_time", "occurred_at DESC", "Newest-first listing and pagination."],
    ["idx_findings_sev", "severity, occurred_at DESC", "Severity filters and the counters."],
    ["idx_findings_rule", "rule, occurred_at DESC", "Per-rule statistics."],
    ["idx_findings_process", "process_id", "Top-process and heatmap aggregation."],
    ["idx_findings_sha256", "file_sha256", "Threat-intel lookups for a hash."],
    ["idx_findings_sev_rank", "severity_rank DESC, occurred_at DESC", "Ordering by severity then time."],
]

API_ROWS = [
    ["GET /", "none", "Dashboard page (index.html), served with the vendored Chart.js bundle."],
    ["GET /vendor/<file>", "none", "Only the vendored assets; every other path returns 404."],
    ["GET /api/health", "none", "ok, version, database, engine heartbeat and engine_alive."],
    ["GET /api/findings", "limit (1-500, default 50), offset, severity, rule, q, since, until", "items, total, limit, offset, has_more."],
    ["GET /api/stats", "hours (1-720, default 24)", "totals, by_severity, by_rule, latest, last_finding, engine."],
    ["GET /api/events-per-minute", "minutes (1-1440, default 60)", "Per-minute event buckets."],
    ["GET /api/top-processes", "hours (default 24), limit (1-50, default 10)", "Findings grouped by process."],
    ["GET /api/process-heatmap", "hours (1-72, default 12), top (1-20, default 8)", "Hour-by-process matrix for the heatmap."],
    ["GET /api/export", "format=csv|jsonl plus the /api/findings filters", "CSV (UTF-8 BOM, quoted) or JSONL download, bounded at 10 000 rows."],
    ["GET /findings.json", "none", "Deprecated compatibility view: 50 most recent findings as time/summary/severity."],
]

TEST_ROWS = [
    ["tests/test_detection_rules.py", "14", "Canary writes, renames and deletes; destination canary; rename counted once; mass-change threshold, window and debounce; severity ordering."],
    ["tests/test_database.py", "11", "Schema creation, idempotent dedupe, enrichment, filters, pagination, counters, heartbeat, JSON migration and WAL behaviour."],
    ["tests/test_canary_integrity.py", "10", "Baseline capture, missing/modified/touched/replaced/oversized states, canonical seeding, startup and periodic scans, duplicate suppression and schema upgrade."],
    ["tests/test_attribution.py", "9", "Sysmon XML parsing (single and multi-root), path/time matching, basename fallback, late-event retry budget, honest none."],
    ["tests/test_threat_intel.py", "6", "Feed parsing, streaming SHA-256, cache reuse, size cap, reload on change, cache deadlock regression."],
    ["tests/test_reporting.py", "4", "PDF rendering, throttle window, duplicate rule+path coalescing, queue shutdown."],
    ["tests/test_dashboard_api.py", "8", "Every API route, filters, pagination, export formats, 404 for source files, legacy alias."],
    ["tests/test_lab_guardrails.py", "5", "Marker requirement, dry run, .txt allowlist, symlink skip, reset behaviour."],
]

FR_ROWS = [
    ["FR-1.1", "The engine must watch the configured folder recursively.", "Created, modified, moved and deleted events all reach the detector."],
    ["FR-1.2", "Touching any canary file must raise a Critical finding.", "Renames and deletes raise findings; the destination is still checked."],
    ["FR-1.3", "Ten or more events in ten seconds must raise a High mass-change finding.", "A burst produces one deduplicated finding."],
    ["FR-1.4", "Normal activity must not raise findings.", "The negative control exits 0 with zero rows."],
    ["FR-2.1", "Findings must persist in SQLite and survive restarts.", "Rows remain after a restart; WAL is enabled."],
    ["FR-2.2", "Repeated ingestion must be idempotent.", "dedupe_key is unique; inserts use ON CONFLICT DO NOTHING."],
    ["FR-2.3", "Existing findings.json must be migrated without data loss.", "Rows are copied once and the file is renamed .migrated."],
    ["FR-3.1", "The engine must attribute a write to its process when Sysmon supplies it.", "pid, process name and attribution_method='sysmon' are populated."],
    ["FR-3.2", "Attribution must never fabricate a process.", "Without Sysmon or read access, method is 'none' and pid is NULL."],
    ["FR-4.1", "Affected files must be hashed and checked against the feed.", "file_sha256 is stored; a match raises Confirmed Ransomware."],
    ["FR-5.1", "Every alert must produce a PDF incident report.", "report_path is populated and the file is a valid PDF."],
    ["FR-5.2", "Report generation must not block detection.", "Reports render on a worker with a 12/min throttle."],
    ["FR-6.1", "The dashboard must list findings with server-side filters.", "limit, offset, severity and rule filters change the result set."],
    ["FR-6.2", "The dashboard must export evidence.", "CSV and JSONL downloads match the filtered total."],
    ["FR-6.3", "The server must not expose source code.", "Paths outside index.html and vendor/ return 404."],
    ["FR-7.1", "The system must run in a container as a non-root user.", "The image runs as uid 10001 and writes only to the volume."],
    ["FR-8.1", "The simulator must refuse to run outside a marked lab.", "A missing .repo-canary-lab marker aborts with exit 2."],
    ["FR-9.1", "Canary content must be verified against a persisted baseline at startup and periodically.", "SHA-256, size and mtime are stored; startup_scan and integrity_scan findings are raised."],
    ["FR-9.2", "A canary changed while the engine was stopped must be reported once, without duplicating a live watchdog alert.", "A restart produces exactly one finding; a live alert suppresses the scan duplicate."],
]

NFR_ROWS = [
    ["NFR-1", "Detection latency: a canary write must produce a stored finding within one second."],
    ["NFR-2", "Concurrency: the dashboard must read while the engine writes, with no 'database is locked'."],
    ["NFR-3", "Portability: Windows first, Linux container supported, paths configurable by environment."],
    ["NFR-4", "Offline operation: no internet access at runtime; Chart.js is vendored."],
    ["NFR-5", "Auditability: every alert keeps time, path, rule, severity, process and hash evidence."],
    ["NFR-6", "Safety: the simulator touches only .txt files in a marked lab and never follows symlinks."],
    ["NFR-7", "Observability: heartbeat, rotating log, and a non-zero exit when the observer dies."],
    ["NFR-8", "Maintainability: 67 automated tests and no hidden global state."],
]

TRACE_ROWS = [
    ["FR-1.x", "scripts/detection_rules.py", "test_detection_rules.py (14), negative control"],
    ["FR-2.x", "scripts/database.py", "test_database.py (11), restart in compose"],
    ["FR-3.x", "scripts/attribution.py", "test_attribution.py (9), live Sysmon run (8/8)"],
    ["FR-4.x", "scripts/threat_intel.py", "test_threat_intel.py (6), hash-match drill"],
    ["FR-5.x", "scripts/reporting.py", "test_reporting.py (4), 4 PDFs per drill"],
    ["FR-6.x", "scripts/dashboard_server.py, index.html", "test_dashboard_api.py (8), container checks"],
    ["FR-7.x", "Dockerfile, docker-compose.yml", "22-step build, 65/65 compose checks"],
    ["FR-8.x", "simulate_ransomware.py", "test_lab_guardrails.py (5)"],
    ["FR-9.x", "scripts/canary_integrity.py", "test_canary_integrity.py (10), restart drill"],
]

ENV_ROWS = [
    ["REPO_CANARY_LAB", r"C:\RansomwareLab", "Lab root; all other paths default beneath it."],
    ["REPO_CANARY_TEST_DIR", r"<lab>\testdata", "Folder the engine watches."],
    ["REPO_CANARY_MONITORED_DIR", r"<lab>\monitored", "Folder used by the simple monitors."],
    ["REPO_CANARY_DB", r"<lab>\canary.db", "SQLite database."],
    ["REPO_CANARY_FINDINGS", r"<lab>\findings.json", "Legacy JSON, read once and migrated."],
    ["REPO_CANARY_REPORTS", r"<lab>\reports", "PDF incident reports."],
    ["REPO_CANARY_HASHES", r"<lab>\known_hashes.txt", "Local SHA-256 feed."],
    ["REPO_CANARY_LOG", r"<lab>\error_log.txt", "Rotating engine log."],
]


def report() -> Document:
    return Document(
        key="report",
        filename="01_Project_Report.pdf",
        title="Project Report",
        subtitle=(
            "Consolidated report: detection design, SQLite evidence store, Sysmon "
            "attribution, PDF incidents, dashboard, packaging and verification."
        ),
        blocks=[
            ("h1", "1. Introduction"),
            ("p", "Ransomware encrypts a victim's files and holds them for payment. The damage is done in "
                  "seconds, so a defender's most valuable asset is early, trustworthy evidence of what is "
                  "happening and which process is doing it. Repo-Canary (project RANSOMWARE 207) is an "
                  "incident-detection system for a Windows server that watches a protected folder, raises an "
                  "alert the moment a canary file is touched or a mass file change begins, attributes the "
                  "writing process, hashes the affected file against a local threat-intel feed, and produces a "
                  "PDF incident report while a dashboard shows the live picture. A persisted canary baseline also "
                  "covers changes made while the engine was stopped, so the evidence survives restarts."),
            ("p", "This version is a production-grade refactor of the original prototype. The prototype kept "
                  f"findings in a flat findings.json capped at 50 entries and could not say which process wrote "
                  f"a file. The current system (version {VERSION}) stores evidence in SQLite, attributes writes "
                  "through Sysmon Event ID 11 with an explicit honest fallback, generates PDF incident reports "
                  "asynchronously, serves a paginated JSON API feeding a Chart.js dashboard, and ships as a "
                  "non-root Docker image that was built and exercised end to end."),
            ("h1", "2. Objectives"),
            ("num", [
                "Detect tampering with three canary files and mass file modification inside the lab folder.",
                "Verify the canaries against a persisted baseline at startup and on an interval, so downtime does not hide tampering.",
                "Persist every alert in a queryable store that survives restarts and concurrent readers.",
                "Attribute a file write to the process that performed it, or state plainly that it could not.",
                "Enrich affected files with SHA-256 hashes and a local threat-intelligence feed.",
                "Produce a PDF incident report per alert without slowing the detection path.",
                "Expose the findings through a paginated HTTP API and a live dashboard.",
                "Package the system so it runs identically on a Windows lab VM and in a container.",
                "Prove the behaviour with an automated suite and recorded end-to-end evidence.",
            ]),
            ("h1", "3. System architecture"),
            ("p", "The system is deliberately split into four processes-worth of responsibility: a filesystem "
                  "observer, a detection engine with asynchronous enrichment, a separate read-only dashboard "
                  "server, and a simulator that plays the attacker for drills. The only shared state is the "
                  "SQLite database plus the report directory on disk, which is what allows the engine and the "
                  "dashboard to run as two containers against one volume."),
            ("bullets", [
                "Observer: watchdog's recursive Observer emits created, modified, moved and deleted events.",
                "Detector: applies the canary and mass-change rules and writes the finding immediately.",
                "Integrity monitor: hashes the canaries against the persisted baseline at startup and every interval.",
                "Enrichment worker: Sysmon attribution, SHA-256 hashing and intel lookup, off the watchdog thread.",
                "Counter flusher: batches event counts per minute every two seconds.",
                "Reporter: renders PDFs on a worker thread with a throttle.",
                "Dashboard server: read-only HTTP JSON API and static page.",
            ]),
            ("h3", "3.1 Data flow"),
            ("code", "file write  ->  watchdog event  ->  rule match  ->  INSERT findings (dedupe_key)\n"
                     "                                        |\n"
                     "                                        +-> enrichment queue -> Sysmon Event 11\n"
                     "                                                               -> SHA-256 feed\n"
                     "                                                               -> report queue -> PDF\n"
                     "dashboard  <- GET /api/*  <- SQLite (WAL)  <- engine heartbeat\n"
                     "canary_baseline -> startup/periodic scan -> findings (startup_scan / integrity_scan)"),
            ("p", "Persistence happens before enrichment on purpose: an alert is never lost because Sysmon was "
                  "slow, a hash took two seconds, or a PDF failed. Enrichment updates the row afterwards."),
            ("h2", "3.2 Timing and latency"),
            ("p", "The path from a write to a stored finding is short by design: watchdog delivers the event, the "
                  "rule check is in memory, and the insert happens on the observer thread before any enrichment. "
                  "Hashing, Sysmon correlation and PDF rendering are queued, so a slow disk or a slow channel "
                  "delays the evidence around a finding, never the finding itself. In the drill the three canary "
                  "findings were stored within milliseconds of the writes, and their attribution arrived about a "
                  "second later, once Sysmon had written its records."),
            ("h1", "4. Detection rules"),
            ("h2", "4.1 Canary rule"),
            ("p", "Three disposable files (_canary_01.txt, _canary_02.txt, _canary_03.txt) are seeded into the "
                  "watched folder. Any create, modify, move or delete that touches one of them raises a "
                  "Critical finding. Renames are counted once, on the source path, while the destination is "
                  "still canary-checked, so moving a canary onto another canary name cannot hide the event."),
            ("h2", "4.2 Mass-change rule"),
            ("p", "The engine keeps a sliding window of file events. When ten or more events are observed inside "
                  "ten seconds, it raises a High mass-change finding. A 0.5-second debounce per rule keeps a "
                  "burst from producing one row per file, and the event counters behind the chart are updated "
                  "once per source event, not once per rule hit."),
            ("h2", "4.3 Threat-intel match"),
            ("p", "Every affected file is hashed with SHA-256 (streamed, with a 256 MiB cap) and compared with the "
                  "local feed. A match upgrades the finding to Confirmed Ransomware, the highest severity rank, "
                  "and records the matched hash and label. The feed is plain text, one '<sha256>  <label>' per "
                  "line, reloaded automatically when it changes."),
            ("h2", "4.4 Severity model"),
            ("p", "Severity is an explicit, ordered value rather than a string that sorts alphabetically. The "
                  "numeric rank is stored beside it, so ordering and filters stay correct in SQL and in the UI."),
            ("table", ["Severity", "Rank", "Raised by", "Meaning"], [
                ["Confirmed Ransomware", "5", "Hash match", "The file matches a known sample in the local feed."],
                ["Critical", "4", "Canary rule", "A protected canary file was touched."],
                ["High", "3", "Mass-change rule", "Ten or more file events in ten seconds."],
                ["Medium", "2", "Extension point", "Reserved for future rules."],
                ["Low", "1", "Extension point", "Reserved for future rules."],
                ["Info", "0", "Migration", "Imported legacy entry without a matching rule."],
            ], [22, 8, 22, 48]),
            ("h2", "4.5 Detection continuity across restarts"),
            ("p", "watchdog only reports events while the engine is running, so a canary changed during a restart "
                  "would otherwise leave no trace. reset_lab.py therefore stores a SHA-256/size/mtime baseline for "
                  "each canary in the canary_baseline table. The engine verifies that baseline once before it "
                  "starts watching and then every --integrity-interval seconds (300 by default; 0 keeps the "
                  "startup scan only). A missing, modified, touched, oversized, unreadable or replaced canary "
                  "raises the same Critical canary finding with event type startup_scan or integrity_scan."),
            ("p", "A live watchdog alert marks the canary as already reported, so the next periodic scan does not "
                  "create a duplicate. A state change still escalates: a canary reported as modified and then "
                  "deleted produces a second, more severe finding. If an older database has no baseline, rows are "
                  "seeded only when the file is byte-for-byte the canonical canary, so an upgrade cannot bless a "
                  "tampered file."),
            ("h1", "5. Evidence store"),
            ("p", "findings.json is gone as a primary store. Evidence now lives in canary.db, a SQLite database in "
                  "WAL mode with a busy timeout and a connection per operation, so the engine can write while the "
                  "dashboard reads. Findings carry UTC ISO-8601 timestamps and a numeric severity_rank, which "
                  "keeps ordering and correlation correct across hosts and time zones."),
            ("p", "Every row has a dedupe_key and the insert uses ON CONFLICT DO NOTHING. That makes ingestion "
                  "idempotent across restarts, concurrent starts and repeated alerts, and it deliberately avoids "
                  "INSERT OR REPLACE, which would delete and re-insert the row and discard enrichment."),
            ("table", ["Table", "Columns", "Purpose"], SCHEMA_ROWS, [18, 46, 36]),
            ("p", "A legacy findings.json found next to the database is migrated once and renamed to "
                  "findings.json.migrated; the migration never deletes the original evidence file."),
            ("h2", "5.1 Write path and idempotency"),
            ("p", "The engine derives a dedupe key from the rule, the path and a one-minute bucket, then inserts "
                  "with ON CONFLICT(dedupe_key) DO NOTHING. INSERT OR REPLACE is deliberately avoided: it deletes "
                  "and re-inserts the row, which resets the primary key and discards enrichment that is already "
                  "attached. Process rows are de-duplicated into the processes table and referenced by foreign key, "
                  "so one image is stored once no matter how many findings mention it."),
            ("h2", "5.2 Concurrency"),
            ("p", "WAL mode plus a busy timeout means the dashboard's reads never block the engine's write, and "
                  "each operation opens its own short-lived connection, so no connection state is shared between "
                  "threads. The trade-off is a slightly higher per-operation cost, which is irrelevant at the event "
                  "rates of this lab and keeps the failure modes simple."),
            ("h2", "5.3 Backup and retention"),
            ("p", "Backing up the lab means copying canary.db together with its -wal and -shm companions while "
                  "the engine runs, plus the reports directory. Nothing is pruned automatically today; a retention "
                  "policy is listed in the future scope."),
            ("h2", "5.4 Schema evolution"),
            ("p", "schema_meta stores the schema version and one-off flags, so a future change can be applied "
                  "once and recorded. Schema version 3 adds the canary_baseline table to the SQLite design; the "
                  "upgrade is additive, so a version-2 database gains the table on its next start. The migration "
                  "flag prevents a second import of the same legacy findings.json."),
            ("h1", "6. Process attribution"),
            ("p", "watchdog reports a path, not a PID, and psutil cannot tell which process wrote a file. The only "
                  "honest source of attribution is a kernel event that carries the PID: on Windows, Sysmon Event "
                  "ID 11 (FileCreate). The engine correlates the finding's path and timestamp with recent Event 11 "
                  "records, then enriches the PID with psutil (image name, path, command line, user)."),
            ("p", "Correlation uses a three-second window, normalised paths, and a same-directory/same-basename "
                  "fallback for rename records. Because watchdog usually observes a write a few hundred "
                  "milliseconds before Sysmon writes its record, a lookup re-reads the channel up to three times, "
                  "0.4 seconds apart, bypassing its half-second cache. If no record matches, the finding stores "
                  "attribution_method='none' and no process: the system never fabricates a PID."),
            ("p", "The engine account must be able to read Microsoft-Windows-Sysmon/Operational. The attribution "
                  "probe reads one record at startup, so an account that cannot read the channel produces an "
                  "honest 'none' plus an actionable warning instead of a misleading 'sysmon' banner."),
            ("h2", "6.1 Verification against live Sysmon"),
            ("p", "Attribution was not accepted on unit tests alone. Sysmon 15.22 was installed with the repository "
                  "configuration and the engine was run against a real drill in the lab. Every finding carried the "
                  "simulator's PID and image, and a second run on the same database reached eight of eight "
                  "attributed rows with two distinct PIDs, which shows the correlation is per event rather than a "
                  "value cached at startup."),
            ("code", "id=1 canary       Critical pid=20656 method=sysmon process=python.exe\n"
                     "id=2 canary       Critical pid=20656 method=sysmon process=python.exe\n"
                     "id=3 canary       Critical pid=20656 method=sysmon process=python.exe\n"
                     "id=4 mass_change  High     pid=20656 method=sysmon process=python.exe"),
            ("p", "Two controls make this claim meaningful. Without Sysmon, or with an account that cannot read the "
                  "channel, the same drill produces attribution_method='none' and no process. And an unknown path "
                  "never matches: a lookup for a file that Sysmon did not record returns none even when other "
                  "events are present in the window."),
            ("h1", "7. Threat intelligence"),
            ("p", "The feed is local and offline by design: a text file of SHA-256 hashes with labels. Entries are "
                  "parsed once, mirrored into the known_hashes table, cached in an LRU cache keyed by path, size and "
                  "modification time, and reloaded when the file changes. Hashing is streamed in chunks so a large "
                  "file cannot exhaust memory, and files above the size cap are skipped with the reason recorded."),
            ("p", "The feed format is deliberately boring so it can be produced by hand, by a script or by another "
                  "tool without conversion."),
            ("code", "# known_hashes.txt - one entry per line, hash then label\n"
                     "5d41402abc4b2a76b9719d911017c592...  Ransomware.Lab.Sample.A\n"
                     "7b8b965ad4bca0e41ab51de7b31363a1...  Ransomware.Lab.Sample.B"),
            ("p", "The file is re-parsed when its size or modification time changes, so an analyst can drop a new "
                  "hash in during an incident without restarting the engine; the mirror in known_hashes follows "
                  "the same reload."),
            ("h1", "8. Incident reports"),
            ("p", "Each alert queues a PDF incident report rendered with fpdf2: header, severity, rule, host, "
                  "timestamp, path, process details, hash, intel label and the surrounding evidence. Rendering "
                  "happens on a dedicated worker, so the watchdog thread never blocks on I/O. Reports are "
                  "throttled to twelve per minute and coalesced per rule and path within a minute; the resulting "
                  "path is written back to the finding."),
            ("h1", "9. Dashboard and API"),
            ("p", "dashboard_server.py is a small read-only HTTP server on the loopback interface. It serves only "
                  "index.html and the vendored Chart.js bundle; source files, .git and every other path return 404. "
                  "The API is paginated and filtered on the server so the browser never loads the whole table."),
            ("table", ["Route", "Parameters", "Returns"], API_ROWS, [26, 34, 40]),
            ("p", "The page shows severity counters, an events-per-minute line chart, a process heatmap, a "
                  "latest-detection card and a paginated findings table with severity, rule and free-text "
                  "filters, plus CSV and JSONL export. It polls the API every two seconds and surfaces the engine "
                  "heartbeat, so a stalled engine is visible in the UI."),
            ("h2", "9.1 Filters and pagination"),
            ("p", "Filtering and paging happen in SQL, not in the browser: the page requests one slice, the server "
                  "returns items, total and has_more, and the UI renders the count from the server. A page is "
                  "capped at 500 rows (50 by default) and the text filter matches the summary and the path, so an "
                  "analyst can search for a filename without exporting anything."),
            ("h2", "9.2 Export safety"),
            ("p", "CSV quotes every field, prefixes a UTF-8 BOM so Excel detects the encoding, and neutralises "
                  "leading =, +, - and @ characters so a crafted filename cannot become a spreadsheet formula. "
                  "JSONL contains one finding per line and is bounded like the CSV at ten thousand rows."),
            ("h1", "10. Packaging and deployment"),
            ("p", "The repository ships a multi-stage Dockerfile (python:3.12-slim), a compose file and a POSIX "
                  "entrypoint. Dependencies are built into a wheelhouse in the builder stage and installed with "
                  "--no-index in the runtime stage, so the image needs no compiler and no network at install "
                  "time. The container runs as uid 10001 (canary), keeps its lab state on the /data volume and "
                  "exposes port 8000."),
            ("bullets", [
                "engine service: detection engine, restart unless-stopped, no published port.",
                "dashboard service: read-only API, published on 127.0.0.1:8000, healthcheck against /api/health.",
                "canary-data volume: SQLite database, testdata, reports and the log, shared by both services.",
            ]),
            ("p", "The image was built and the stack was run end to end on a Docker host: 22 build steps, a 188 MB "
                  "image, a healthy dashboard and a full simulated attack through the containers."),
            ("code", "services:\n  engine:\n    build: .\n    command: [\"engine\"]\n    volumes: [canary-data:/data]\n"
                     "  dashboard:\n    build: .\n    command: [\"dashboard\"]\n    ports: [\"127.0.0.1:8000:8000\"]\n"
                     "    volumes: [canary-data:/data]\n    depends_on: [engine]\nvolumes:\n  canary-data:"),
            ("h1", "11. Testing and verification"),
            ("p", "The suite contains 67 tests across eight modules, plus a negative-control script and recorded "
                  "end-to-end runs. The tests avoid the filesystem where possible and exercise the rules, the "
                  "database, canary baseline capture and scans, the Sysmon XML parser, the threat-intel cache, the "
                  "PDF writer, the HTTP API and the simulator guardrails."),
            ("table", ["Module", "Tests", "Coverage"], TEST_ROWS, [26, 8, 66]),
            ("h2", "11.1 Recorded evidence"),
            ("bullets", [
                "pytest: 67 passed.",
                "Negative control: three creates, one append, one rename and one delete produced zero alerts.",
                "Live Sysmon run: three Critical canary findings and one High mass-change finding, all attributed "
                "to python.exe with attribution_method='sysmon' (8/8 attributed across two runs, two distinct PIDs).",
                "Docker: image built, compose stack healthy, 65/65 API and runtime checks, findings survived a restart.",
                "End-to-end lab run: 3 Critical + 1 High findings, four PDF reports, heartbeat present, no tracebacks.",
                "Restart continuity: a canary modified while the engine was stopped produced exactly one Critical startup_scan finding; six seconds of periodic scans produced no duplicate.",
            ]),
            ("h2", "11.2 Negative control"),
            ("p", "A detector that alerts on everything would pass an attack test, so the suite includes the "
                  "opposite check: six ordinary operations in the lab, then an assertion that the findings table "
                  "is still empty. The script seeds the three canaries first, so the startup integrity scan has a "
                  "healthy baseline and the result measures ordinary activity rather than missing files."),
            ("code", "Activity:   3 creates, 1 append, 1 rename, 1 delete\n"
                     "Expectation: no alert\nAlerts:     0\n"
                     "[PASS] Normal activity produced no alert (no false positive)."),
            ("h2", "11.3 Defects found by running it live"),
            ("p", "The live Sysmon run was worth more than the unit tests: it exposed three defects that only a "
                  "real channel and a real filesystem could reveal."),
            ("num", [
                "Attribution raced Sysmon. The enrichment worker looked up the PID once and immediately, but "
                "watchdog reports a write a few hundred milliseconds before Sysmon ghosts its record, so live "
                "findings were always unattributed. The lookup now re-reads the channel up to three times.",
                "The Sysmon configuration filtered nothing. An exclude rule with no condition matches nothing, so "
                "every process create and terminate was logged and Event ID 11 was crowded out. The rule now "
                "carries an always-true image condition.",
                "The availability check lied. wevtutil accepts a channel query for a non-elevated account but "
                "denies the event read, so the banner promised sysmon while every lookup failed. The check now "
                "probes one record.",
                "Canary bytes drifted from the baseline. reset_lab used text mode, which writes CRLF on Windows "
                "while the canonical baseline is LF, so a fresh lab could look tampered. Canaries are now written "
                "as bytes, and seeding accepts only the exact canonical LF or legacy CRLF form.",
            ]),
            ("h2", "11.4 Container verification"),
            ("p", "The image built in 22 steps to 188 MB and the compose stack reported a healthy dashboard. "
                  "Inside the containers the API returned the expected payloads, CSV and JSONL exports matched "
                  "the reported total, source files returned 404, and the findings survived a restart of both "
                  "services. Containers have no Sysmon, so attribution there is 'none' by design."),
            ("h1", "12. Security and limitations"),
            ("h2", "12.1 Assumptions"),
            ("bullets", [
                "The lab folder is disposable and its path is configured, never inferred from the working directory.",
                "The host clock is correct; findings and Sysmon events are compared as UTC.",
                "An analyst, not the tool, decides what an alert means; the system records evidence and never acts.",
                "The Sysmon configuration covers the watched folder; a path outside it cannot be attributed.",
            ]),
            ("bullets", [
                "The dashboard has no authentication and no TLS; it is bound to 127.0.0.1 and intended for a lab.",
                "Attribution depends on Sysmon and on read access to its channel (elevated or Event Log Readers).",
                "Threat intelligence only matches known SHA-256 samples; it cannot detect a zero-day sample.",
                "The system detects and reports. It does not contain, quarantine or recover files.",
                "The integrity baseline lives in the same SQLite database, so an administrator who can rewrite canary.db can also rewrite the baseline.",
                "The integrity scan covers the three canary files only; mass-change activity that happens while the engine is stopped cannot be reconstructed from the filesystem.",
                "PDF generation is throttled; a burst intentionally coalesces duplicates for the same rule and path.",
                "Containers have no Sysmon, so attribution is 'none' there by design; run natively for attribution.",
                "Docker bind mounts on Windows may not propagate inotify events; use the named volume or run natively.",
            ]),
            ("h1", "13. Requirements traceability"),
            ("p", "Each requirement group maps to one implementation area and to the test or run that demonstrates "
                  "it. Nothing in the specification is left without evidence."),
            ("table", ["Requirement", "Implementation", "Evidence"], TRACE_ROWS, [16, 34, 50]),
            ("h1", "14. Future scope"),
            ("p", "The next steps are alert delivery (email or webhook), authentication and TLS for the dashboard, a "
                  "retention policy for old findings and PDFs, entropy-based detection for files that are renamed "
                  "after modification, a Windows service wrapper, and multi-host aggregation behind a single "
                  "dashboard. Decision-model triage was explicitly out of scope for this pass; the enrichment "
                  "stage is the natural place to add it later."),
            ("h1", "15. Conclusion"),
            ("p", "Repo-Canary now produces evidence a responder can act on: when a canary file was touched, how "
                  "large the burst was, which process did it, whether the file matches known ransomware, and a PDF "
                  "that records all of it. The refactor replaced a fragile JSON file with a concurrent SQLite "
                  "store, replaced guessing with Sysmon correlation and an honest fallback, added restart-proof "
                  "canary integrity checks, and made the whole system reproducible on another machine through "
                  "Docker and a 67-test suite."),
            ("h1", "16. References"),
            ("bullets", [
                "Microsoft Sysinternals, Sysmon v15 documentation and event schema (Event ID 11, FileCreate).",
                "watchdog, psutil and fpdf2 project documentation.",
                "SQLite documentation: WAL mode, busy timeout and UPSERT semantics.",
                "Docker documentation: multi-stage builds, named volumes and healthchecks.",
                "MITRE ATT&CK, T1486 - Data Encrypted for Impact.",
            ]),
            ("h1", "Appendix A - Database schema"),
            ("table", ["Index", "Columns", "Used for"], INDEX_ROWS, [22, 34, 44]),
            ("h3", "Example queries"),
            ("code", "SELECT rule, COUNT(*) FROM findings GROUP BY rule ORDER BY 2 DESC;\n"
                     "SELECT occurred_at, severity, rule, path, pid, attribution_method\n"
                     "  FROM findings ORDER BY occurred_at DESC LIMIT 20;\n"
                     "SELECT p.name, COUNT(*) FROM findings f\n"
                     "  JOIN processes p ON p.id = f.process_id GROUP BY p.name;"),
            ("h1", "Appendix B - Configuration"),
            ("table", ["Variable", "Default", "Meaning"], ENV_ROWS, [30, 26, 44]),
            ("p", "Engine flag --integrity-interval controls the baseline scan period. The default is 300 "
                  "seconds; 0 runs the startup scan only. The engine also accepts --attribution auto|sysmon|none, "
                  "--no-reports, --report-dir, --hash-file and --max-hash-bytes."),
        ],
    )


def srs() -> Document:
    return Document(
        key="srs",
        filename="02_SRS_Document.pdf",
        title="Software Requirements Specification",
        subtitle="Functional and non-functional requirements for the current implementation.",
        blocks=[
            ("h1", "1. Purpose and scope"),
            ("p", "This document specifies what the Ransomware 207 incident-detection system must do. The scope is "
                  "detection and evidence on a single Windows host: watch a disposable folder, detect canary "
                  "tampering and mass modification, attribute the writing process, enrich with hashes and threat "
                  "intelligence, report, and expose the evidence locally. Automated containment and file recovery "
                  "are out of scope."),
            ("h1", "2. Definitions"),
            ("bullets", [
                "Canary file: a disposable file whose modification is itself the alarm.",
                "Mass change: ten or more file events inside ten seconds.",
                "Attribution: identifying the process that wrote a file, from kernel evidence.",
                "Finding: one persisted alert row with its evidence.",
                "Canary baseline: the expected SHA-256, size and modification time of a canary, stored in SQLite.",
                "Honest fallback: recording 'none' rather than guessing a process.",
            ]),
            ("h1", "3. Stakeholders"),
            ("bullets", [
                "Security analyst: reads findings, filters them, exports evidence.",
                "Lab operator: runs drills, resets the lab, applies the Sysmon configuration.",
                "Developer: extends rules and enriches findings.",
                "Faculty reviewer: needs reproducible evidence and a traceable requirement set.",
            ]),
            ("h1", "4. Functional requirements"),
            ("table", ["ID", "Requirement", "Acceptance"], FR_ROWS, [10, 46, 44]),
            ("h1", "5. Non-functional requirements"),
            ("table", ["ID", "Requirement"], NFR_ROWS, [12, 88]),
            ("h1", "6. Constraints"),
            ("bullets", [
                "Windows process attribution requires Sysmon 15 (or compatible) and read access to its channel.",
                "The dashboard is loopback-only, with no authentication or TLS.",
                "Threat intelligence is a local hash list; there is no cloud lookup.",
                "The canary baseline is stored in the same SQLite database as the findings; protecting the database is part of the host security model.",
                "Python 3.12+ is required; runtime dependencies are watchdog, psutil and fpdf2.",
            ]),
            ("h1", "7. Acceptance"),
            ("p", "The system is accepted when the full test suite passes, the negative control produces no "
                  "findings, a simulated attack produces canary and mass-change findings with PDF reports, a live "
                  "Sysmon run attributes those findings to the writing process, a canary changed while the engine "
                  "was stopped is reported by the startup integrity scan exactly once, and the compose stack "
                  "starts healthy and serves the same evidence over HTTP."),
        ],
    )


def architecture() -> Document:
    return Document(
        key="architecture",
        filename="01_System_Architecture.pdf",
        title="System Architecture",
        subtitle="Components, data flow, concurrency model and deployment topologies.",
        blocks=[
            ("h1", "1. Overview"),
            ("p", "Repo-Canary is a set of cooperating processes around one SQLite database. The engine owns "
                  "writes; the dashboard server owns reads; the simulator stands in for an attacker during drills. "
                  "Nothing is shared through memory, which is what allows a native Windows run and a two-container "
                  "deployment to use the same code."),
            ("figure_wide", str(IMAGES / "architecture.png"),
             "Figure 1. The whole system on one page: watchdog and rules persist first; the integrity monitor "
             "shares the same findings table; enrichment and PDF rendering are asynchronous; the dashboard reads SQLite."),
            ("h2", "1.1 End-to-end walkthrough"),
            ("num", [
                "reset_lab.py writes the three canaries and their SHA-256/size/mtime baseline, then creates the disposable files and marker.",
                "The engine opens canary.db, creates or upgrades the schema, migrates a legacy findings.json once, and loads the local hash feed.",
                "It probes Sysmon for a readable Event ID 11 record; if the channel is missing or denied, attribution is disabled honestly.",
                "The startup integrity scan compares the canaries with the baseline before watchdog starts, so downtime cannot hide tampering.",
                "watchdog starts a recursive observer on the lab folder and the engine prints Status: WATCHING.",
                "A write or rename reaches RansomwareDetector; the 0.5-second debounce collapses duplicate deliveries.",
                "DetectionRules checks the canary name and the rolling 10-events/10-seconds mass-change window.",
                "The finding is inserted with a unique dedupe_key before any slow work; the enrichment job is queued.",
                "The worker correlates Sysmon Event ID 11, expands the PID with psutil, hashes the file and checks the feed.",
                "The reporter renders a throttled PDF and attaches its path to the finding.",
                "The dashboard polls the API every two seconds and shows the new row, counters, chart and latest card.",
                "A heartbeat is written every five seconds; if it goes stale, the dashboard warns that the engine is down.",
            ]),
            ("h1", "2. Components"),
            ("table", ["Component", "File", "Responsibility"], [
                ["Engine", "scripts/detection_engine.py", "Observer, rules, persistence, enrichment queue, counters, heartbeat, shutdown."],
                ["Rules", "scripts/detection_rules.py", "Canary and mass-change decisions, event counting."],
                ["Database", "scripts/database.py", "Schema, WAL connections, dedupe insert, queries, migration, heartbeat."],
                ["Canary integrity", "scripts/canary_integrity.py", "Persisted baseline, capped hashing, startup/periodic scans and duplicate suppression."],
                ["Attribution", "scripts/attribution.py", "Sysmon Event ID 11 parsing and correlation, psutil enrichment."],
                ["Threat intel", "scripts/threat_intel.py", "Feed parsing, streaming SHA-256, cache, reload."],
                ["Reporting", "scripts/reporting.py", "PDF rendering, throttle, async queue."],
                ["Dashboard", "scripts/dashboard_server.py", "Read-only JSON API and static page."],
                ["UI", "index.html", "Chart.js charts, heatmap, filters, pagination, export."],
                ["Simulator", "simulate_ransomware.py", "Harmless drill: reverse text and rename inside a marked lab."],
            ], [16, 30, 54]),
            ("h1", "3. Data flow"),
            ("code", "watchdog Observer\n"
                     "   |  (create / modify / move / delete)\n"
                     "   v\n"
                     "RansomwareDetector --rule match--> INSERT INTO findings (dedupe_key UNIQUE)\n"
                     "   |                                     |\n"
                     "   |                                     +--> EnrichmentWorker\n"
                     "   |                                            |-- Sysmon Event 11 -> psutil\n"
                     "   |                                            |-- SHA-256 -> intel feed\n"
                     "   |                                            +-- IncidentReporter -> PDF\n"
                     "   +--> EventCounters (buffered, flushed every 2 s)\n"
                     "Engine heartbeat (5 s) --> engine_state\n"
                     "canary_baseline --> startup + periodic scans --> findings (startup_scan / integrity_scan)\n"
                     "Dashboard --> SELECT ... --> JSON --> index.html"),
            ("h3", "3.1 Restart continuity"),
            ("p", "The observer only sees events while the engine runs. A separate CanaryIntegrityMonitor reads the "
                  "persisted baseline from SQLite and checks all three canaries before the observer starts, then "
                  "on an interval (300 seconds by default). It emits the same Critical canary finding for a missing, "
                  "modified, timestamp-touched, oversized, unreadable or replaced file, with event type "
                  "startup_scan or integrity_scan. A live watchdog alert marks that canary as reported, so the "
                  "next scan does not duplicate it; a later state change still escalates."),
            ("h1", "4. Concurrency"),
            ("bullets", [
                "The watchdog callback never performs I/O beyond the finding insert.",
                "One enrichment thread serialises Sysmon queries and hashing; the queue is bounded at 1000 jobs and drops loudly.",
                "One reporter thread serialises PDF rendering behind a throttle.",
                "Counters are buffered in memory and flushed every two seconds to minimise write amplification.",
                "One integrity thread performs the startup scan before the observer starts and then sleeps on the configured interval.",
                "Each database operation opens its own connection with WAL and a busy timeout, so the dashboard never blocks the engine.",
                "SIGINT and SIGTERM set a stop event; the observer, workers and heartbeat drain before exit.",
            ]),
            ("h1", "5. Failure handling"),
            ("table", ["Failure", "Behaviour"], [
                ["Observer thread dies", "The main loop notices and exits 1 so a supervisor restarts the service."],
                ["Sysmon missing or unreadable", "Attribution probes one record; findings store 'none' with a warning."],
                ["Canary changed while stopped", "The startup integrity scan raises one Critical canary finding with event type startup_scan."],
                ["Baseline missing in an old database", "Rows are seeded only from the exact canonical canary bytes; any other content is reported as modified."],
                ["Canary unreadable or oversized", "The capped scan reports unreadable, oversized or replaced without reading an unbounded file."],
                ["Threat feed missing", "The engine runs with zero hashes and logs a single warning."],
                ["PDF rendering fails", "The finding keeps its row and report_path stays NULL; the error is logged."],
                ["Dashboard starts first", "It serves an empty result set until the engine creates the schema."],
                ["Legacy findings.json present", "Migrated once, then renamed to .migrated."],
            ], [30, 70]),
            ("h1", "6. Deployment"),
            ("h2", "6.1 Native Windows lab"),
            ("p", "Python 3.12 virtual environment, Sysmon installed with Sysmon/sysmonconfig.xml, engine and "
                  "dashboard started from scripts/, database and reports under C:\\RansomwareLab."),
            ("h2", "6.2 Containers"),
            ("p", "One image, two services. The entrypoint initialises the lab on the shared canary-data volume, "
                  "then execs either the engine or the dashboard. The dashboard publishes 127.0.0.1:8000 and its "
                  "healthcheck calls /api/health. The image is non-root and installs dependencies from an offline "
                  "wheelhouse."),
            ("h1", "7. Security boundaries"),
            ("p", "The engine needs write access to the lab folder and read access to the Sysmon channel; the "
                  "dashboard needs only read access to the database. The dashboard serves exactly two things - the "
                  "page and the vendored assets - which removes the original prototype's accidental exposure of "
                  "the repository over HTTP."),
            ("h1", "8. Design decisions and trade-offs"),
            ("table", ["Decision", "Why it was chosen", "Trade-off"], [
                ["SQLite with WAL", "One file, real transactions, indexed queries and concurrent readers without a server.", "Single-host store; a fleet needs a collector later."],
                ["watchdog Observer", "Event-driven detection with recursive coverage and no polling interval.", "Events exist only while the process runs, so the baseline scan covers restarts."],
                ["Sysmon Event ID 11", "The only honest source of the writing PID; watchdog carries no process identity.", "Requires Sysmon and read access to its channel; otherwise attribution is 'none'."],
                ["Persisted canary baseline", "Catches changes made while the engine was stopped or an event was missed.", "Covers three canaries only; mass-change during downtime is not reconstructable."],
                ["Persist before enrich", "Sysmon lag, hashing or PDF rendering cannot lose the alert.", "Rows are briefly incomplete until the worker updates them."],
                ["Unique dedupe_key", "Restarts, concurrent starts and repeated alerts stay idempotent.", "Two genuinely different events in the same second/path/rule bucket collapse."],
                ["Async PDF throttle", "A burst cannot spawn hundreds of PDF renders or files.", "Some duplicate rule+path alerts intentionally coalesce into one report."],
                ["Loopback dashboard", "No authentication or TLS is needed on a single lab host.", "Not safe to publish; keep it on 127.0.0.1."],
                ["Docker named volume", "Windows bind mounts may not propagate inotify events.", "The container path is not directly editable from Windows Explorer."],
            ], [22, 46, 32]),
            ("h1", "9. Limits and assumptions"),
            ("bullets", [
                "The host clock is correct; findings and Sysmon events are compared in UTC.",
                "The Sysmon configuration covers the watched folder; a path outside it cannot be attributed.",
                "The lab folder contains the .repo-canary-lab marker, so the simulator cannot be aimed at real documents.",
                "The baseline and findings live in the same database; an administrator who can rewrite canary.db can rewrite the baseline.",
                "The system detects and reports; it does not contain, quarantine, delete or recover files.",
                "The threat-intel feed only recognises known SHA-256 samples, not zero-day ransomware.",
            ]),
            ("h1", "10. Glossary"),
            ("table", ["Term", "Meaning in this project"], [
                ["Canary file", "A disposable file whose modification is itself the alarm."],
                ["Canary baseline", "The expected SHA-256, size and mtime of a canary, stored in SQLite."],
                ["Mass change", "Ten or more normalised file events inside a rolling ten-second window."],
                ["Finding", "One persisted alert row with its time, severity, path and evidence."],
                ["Dedupe key", "A SHA-256 of rule, normalized path, event type and second bucket; UNIQUE in SQLite."],
                ["Honest fallback", "Recording attribution_method='none' instead of guessing a process."],
                ["Enrichment", "The asynchronous step that adds process, hash and intel fields to a finding."],
            ], [24, 76]),
        ],
    )


def diagrams() -> Document:
    return Document(
        key="diagrams",
        filename="02_Diagrams.pdf",
        title="Diagrams",
        subtitle="Context, data-flow, use-case, sequence, entity-relationship and deployment views of Repo-Canary.",
        blocks=[
            ("h1", "1. How to read this document"),
            ("p", "This document is the visual companion to the System Architecture report. Every figure is "
                  "generated from the same source tree as the implementation and is explained in plain language "
                  "immediately below the image. Read it in order for a complete walkthrough, or open a single "
                  "figure when a professor asks 'show me how this part works'."),
            ("table", ["Figure", "Question it answers"], [
                ["1. Context", "Who uses the system and what enters or leaves it?"],
                ["2. DFD level 1", "Which processes and stores turn a file event into a finding?"],
                ["3. Use cases", "What can each actor do with the system?"],
                ["4. Sequence", "What happens, in order, during one detection?"],
                ["5. ER diagram", "How is the evidence stored and related?"],
                ["6. Deployment", "How does the native lab differ from the Docker stack?"],
            ], [20, 80]),
            ("h1", "2. System context (DFD level 0)"),
            ("figure_wide", str(IMAGES / "diagram_context.png"),
             "Figure 1. The lab operator or simulator changes testdata; Sysmon and the hash feed supply evidence; "
             "the analyst reads findings and PDF reports. canary.db and reports/ are the system's stores."),
            ("p", "The context diagram deliberately hides implementation detail. Repo-Canary is one box because, "
                  "from the outside, the engine and the dashboard are a single service: file activity goes in, "
                  "and findings, charts and PDF reports come out. The two external evidence feeds are what make "
                  "the output defensible: Sysmon supplies the PID, and the local hash feed supplies known-bad "
                  "SHA-256 values."),
            ("h1", "3. Data-flow diagram (DFD level 1)"),
            ("figure_wide", str(IMAGES / "diagram_dfd1.png"),
             "Figure 2. P1/P2 detect and persist; P3 checks the persisted canary baseline; P4 enriches; "
             "P5 reports; P6 serves reads. D1 is the watched folder, D2 the SQLite evidence store, D3 the reports."),
            ("p", "The important design choice is the order: P2 writes the finding to D2 before P4 does any slow "
                  "work. A Sysmon query, a 256 MiB hash or a PDF render can fail or take seconds without losing the "
                  "alert. P3 writes to the same findings table, so a startup/periodic integrity scan appears in the "
                  "dashboard exactly like a live watchdog alert."),
            ("bullets", [
                "P1 watchdog: receives create, modify, move and delete events from the recursive observer.",
                "P2 rules: applies canary, mass-change, debounce and cooldown decisions, then inserts.",
                "P3 integrity: compares each canary's SHA-256/size/mtime with canary_baseline at startup and on an interval.",
                "P4 enrichment: correlates Sysmon Event ID 11, expands the PID with psutil, hashes the file and checks the feed.",
                "P5 reporter: renders a throttled PDF and writes its path back to the finding.",
                "P6 dashboard API: read-only SQL over D2; it never writes and never blocks the engine.",
            ]),
            ("h1", "4. Use-case view"),
            ("figure_wide", str(IMAGES / "diagram_usecase.png"),
             "Figure 3. The lab operator resets the lab and runs the harmless drill; Sysmon supplies attribution; "
             "the security analyst reads and exports the evidence. Hash matching and PDF generation are automatic."),
            ("table", ["Actor", "Capabilities demonstrated"], [
                ["Lab operator / simulator", "Reset/start the lab, run the harmless drill, reset evidence between runs."],
                ["Security analyst", "View dashboard, filter/export findings, open PDF reports, review evidence."],
                ["Sysmon", "Supply Event ID 11 with PID, path and timestamp for attribution."],
            ], [28, 72]),
            ("p", "The use cases are intentionally small. There is no 'contain the process' use case because the "
                  "project is a detection-and-evidence system: it does not quarantine, delete or recover files. "
                  "That boundary is a design decision, not a missing button, and it is stated in the limitations "
                  "of every document."),
            ("h1", "5. Detection sequence"),
            ("figure_wide", str(IMAGES / "diagram_sequence.png"),
             "Figure 4. A canary write becomes a stored finding before enrichment starts; the dashboard polls "
             "the same SQLite database every two seconds."),
            ("num", [
                "The simulator writes or renames a file in the marked lab.",
                "watchdog emits a MODIFIED/MOVED event with the path.",
                "DetectionRules debounces repeats and checks the canary and mass-change rules.",
                "The finding is inserted with a unique dedupe_key and queued for enrichment.",
                "The enrichment worker reads the row and correlates Sysmon Event ID 11.",
                "The worker updates the row with PID, process details, SHA-256 and intel label.",
                "A PDF report job is queued if the throttle allows it.",
                "The report path is written back to the same finding row.",
                "The dashboard's 2-second poll selects the new row.",
                "The browser renders the counter, chart, latest card and table.",
            ]),
            ("h1", "6. Entity-relationship diagram"),
            ("figure_wide", str(IMAGES / "diagram_er.png"),
             "Figure 5. findings is the centre of the model; processes is a reusable dimension; "
             "canary_baseline is the integrity reference; event_counters and engine_state serve the dashboard."),
            ("p", "Only one relationship is enforced by a foreign key: findings.process_id -> processes.id. "
                  "known_hashes is a logical lookup on findings.file_sha256, not a foreign key, because a file "
                  "may be hashed without being in the feed. canary_baseline is keyed by canary name and is read "
                  "by the integrity monitor, not joined to findings. event_counters and engine_state are "
                  "dashboard-support tables with no evidence rows."),
            ("h1", "7. Deployment topology"),
            ("figure_wide", str(IMAGES / "diagram_deployment.png"),
             "Figure 6. Native Windows uses two Python processes and a local lab folder; Docker Compose uses "
             "the same image twice and a shared named volume."),
            ("p", "The deployment diagram shows why the dashboard is safe to run beside the engine: it opens its "
                  "own read-only SQLite connections and never touches the watched folder or the Sysmon channel. "
                  "In containers, the named volume carries testdata, canary.db, reports and logs; because Linux "
                  "containers have no Sysmon, attribution is honestly 'none' there."),
            ("h1", "8. Figure-to-source map"),
            ("table", ["Figure", "Generated by", "Implementation it reflects"], [
                ["1. Context", "docs_src/make_diagrams.py", "scripts/detection_engine.py, dashboard_server.py"],
                ["2. DFD level 1", "docs_src/make_diagrams.py", "engine threads, database, enrichment and reports"],
                ["3. Use cases", "docs_src/make_diagrams.py", "reset_lab, simulator, dashboard and Sysmon integration"],
                ["4. Sequence", "docs_src/make_diagrams.py", "watchdog -> rules -> DB -> workers -> API"],
                ["5. ER", "docs_src/make_diagrams.py", "scripts/database.py SCHEMA_SQL"],
                ["6. Deployment", "docs_src/make_diagrams.py", "Dockerfile, docker-compose.yml, entrypoint"],
            ], [20, 34, 46]),
            ("h1", "9. How to explain the diagrams in a viva"),
            ("bullets", [
                "Start with Figure 1: 'file activity goes in, evidence comes out, and Sysmon/hash feeds make it trustworthy'.",
                "Use Figure 2 to explain that detection is synchronous but enrichment and reporting are asynchronous.",
                "Use Figure 4 when asked what happens in the two seconds after a canary is touched.",
                "Use Figure 5 to justify SQLite and the dedupe/baseline design rather than a JSON file.",
                "Use Figure 6 to explain the Docker limitation: no Sysmon inside Linux containers, so attribution is 'none'.",
            ]),
        ],
    )


def database_doc() -> Document:
    return Document(
        key="database",
        filename="03_Database_Design.pdf",
        title="Database Design",
        subtitle="SQLite schema, indexes, integrity rules and migration from findings.json.",
        blocks=[
            ("h1", "1. Choice of store"),
            ("p", "The prototype wrote a JSON array and truncated it at 50 entries. That lost evidence, could not "
                  "be queried, and corrupted on concurrent access. The current store is SQLite: a single "
                  "canary.db file with no server to install, real transactions, indexes and a WAL mode that lets "
                  "the engine write while the dashboard reads."),
            ("h1", "2. Connection settings"),
            ("code", "PRAGMA journal_mode = WAL;\nPRAGMA synchronous = NORMAL;\nPRAGMA busy_timeout = 5000;\n"
                     "PRAGMA foreign_keys = ON;"),
            ("p", "Every operation opens and closes its own connection. Nothing is shared across threads, so there "
                  "is no cross-thread connection state to corrupt, and WAL keeps readers from blocking the writer."),
            ("h1", "3. Tables"),
            ("table", ["Table", "Columns", "Purpose"], SCHEMA_ROWS, [16, 48, 36]),
            ("figure_wide", str(IMAGES / "diagram_er.png"),
             "Figure 1. The evidence model. findings is the fact table; processes is a reusable dimension; "
             "canary_baseline is the integrity reference; the remaining tables support charts and health."),
            ("h2", "3.1 What each table is for"),
            ("bullets", [
                "findings: one row per alert, with UTC time, severity/rank, rule, trigger_rule, path, event type, process FK, hash, intel label, report path and dedupe key.",
                "processes: a normalized process dimension (name, executable, command line, user, first/last seen) reused by many findings.",
                "known_hashes: a mirror of the local feed, so the evidence store records the intelligence that was loaded.",
                "canary_baseline: the expected SHA-256, size and nanosecond mtime for the three canaries; written by reset_lab and read by the integrity monitor.",
                "event_counters: per-minute event volume used by the dashboard chart; it stores counts, not a row per file event.",
                "engine_state: a single row with the last heartbeat, watch directory and engine version; /api/health reads it.",
                "schema_meta: key/value metadata; the schema_version key records the current schema version, and the legacy-import flag prevents a second migration.",
            ]),
            ("h1", "4. Integrity rules"),
            ("bullets", [
                "severity is constrained to the six allowed values; severity_rank stores the numeric order.",
                "rule is one of hash_match, canary, mass_change or legacy; trigger_rule records which rule fired first.",
                "attribution_method is sysmon, heuristic or none - the column cannot claim an unnamed source.",
                "dedupe_key is UNIQUE, so a restart or a repeated alert cannot duplicate evidence.",
                "processes rows are de-duplicated by (name, exe_path, cmdline) and reused by foreign key.",
                "known_hashes enforces a 64-character SHA-256.",
                "canary_baseline enforces a 64-character SHA-256 and stores size, mtime and capture time for each canary.",
            ]),
            ("h1", "5. Indexes"),
            ("table", ["Index", "Columns", "Used for"], INDEX_ROWS, [22, 32, 46]),
            ("h1", "6. Write path"),
            ("p", "The engine builds an in-memory finding record, derives a dedupe key from the rule, the path and "
                  "a time bucket, and inserts with ON CONFLICT(dedupe_key) DO NOTHING. INSERT OR REPLACE is "
                  "deliberately not used: it deletes and re-inserts the row, which resets the primary key and "
                  "discards enrichment already attached to the evidence."),
            ("h2", "6.1 Canary baseline"),
            ("p", "reset_lab.py writes the three canonical canaries and stores their SHA-256, size and nanosecond "
                  "mtime in canary_baseline. The engine verifies those rows before watchdog starts and on the "
                  "configured interval. Hashing is capped at 1 MiB, and a symlink or non-regular file is reported "
                  "as replaced rather than followed. If a database predates the table, rows are seeded only when "
                  "the file is the exact canonical canary; any other bytes are left to be reported as modified."),
            ("h1", "7. Migration"),
            ("p", "On startup the engine looks for a legacy findings.json beside the database. If present, each "
                  "entry becomes a row with source='json_migration' and rule='legacy', and the file is renamed to "
                  "findings.json.migrated. The original evidence file is never deleted."),
            ("h1", "8. Retention and backup"),
            ("p", "Evidence is append-only during operation. Backing up the lab means copying canary.db (plus the "
                  "-wal and -shm files while the engine runs) and the reports directory. A retention policy is "
                  "listed in the future scope; today nothing is pruned automatically."),
            ("h1", "9. Example queries"),
            ("code", "SELECT severity, COUNT(*) FROM findings GROUP BY severity;\n"
                     "SELECT occurred_at, rule, path, pid, attribution_method\n"
                     "  FROM findings WHERE severity = 'Critical'\n"
                     "  ORDER BY occurred_at DESC LIMIT 10;\n"
                     "SELECT p.name, COUNT(*) AS hits FROM findings f\n"
                     "  JOIN processes p ON p.id = f.process_id\n"
                     "  GROUP BY p.name ORDER BY hits DESC;\n"
                     "SELECT name, sha256, size, mtime_ns, captured_at FROM canary_baseline;"),
            ("h1", "10. Relationships and query patterns"),
            ("table", ["Question", "Query shape"], [
                ["What happened most recently?", "SELECT * FROM findings ORDER BY occurred_at DESC, id DESC LIMIT 50;"],
                ["How many by severity?", "SELECT severity, COUNT(*) FROM findings GROUP BY severity;"],
                ["Which process caused the most findings?", "JOIN processes on process_id, GROUP BY p.id, ORDER BY COUNT(*) DESC."],
                ["What was the events-per-minute trend?", "SELECT minute, SUM(count) FROM event_counters GROUP BY minute."],
                ["Is a canary intact?", "Compare canary_baseline.sha256/size/mtime_ns with the current file in the integrity monitor."],
                ["Is the engine alive?", "SELECT last_heartbeat FROM engine_state WHERE id=1 and compare with UTC now."],
            ], [34, 66]),
            ("h1", "11. Data lifecycle"),
            ("num", [
                "reset_lab.py creates the disposable files and replaces the canary baseline for a clean run.",
                "The engine inserts findings and counters; enrichment updates rows in place; reports attach a path.",
                "The dashboard only reads. WAL allows that read while the engine writes.",
                "--clear-findings empties findings, counters and heartbeat but deliberately leaves canary_baseline intact, because the files are still present.",
                "Backups copy canary.db with its -wal/-shm companions while running, plus the reports directory.",
            ]),
            ("h1", "12. Security and tamper considerations"),
            ("bullets", [
                "The database is local evidence, not a tamper-proof ledger. A host administrator can edit it.",
                "The canary baseline is in the same database it protects; protecting canary.db is part of the host security model.",
                "The dashboard is read-only and loopback-bound, but it has no authentication or TLS.",
                "The reports directory contains the same evidence in PDF form; copying both is the recommended backup.",
                "The database must never be placed on a network share that the ransomware can reach; the lab model assumes a local disk.",
            ]),
            ("h1", "13. Worked example: one canary finding"),
            ("table", ["Column", "Example value", "Why it matters"], [
                ["occurred_at", "2026-11-17T08:53:25.849928Z", "UTC, sortable, comparable with Sysmon UtcTime."],
                ["severity / rank", "Critical / 4", "Display name and numeric ordering without a CASE expression."],
                ["rule / trigger_rule", "canary / canary", "trigger_rule survives an upgrade to hash_match."],
                ["path", "...\\testdata\\_canary_01.txt", "Exact file the responder must inspect."],
                ["event_type", "MODIFIED", "What the observer saw; startup scans use startup_scan."],
                ["dedupe_key", "sha256(rule|path|event|second)", "Idempotent across restarts and repeated delivery."],
                ["process_id / pid", "7 / 20656", "Reusable process dimension and the concrete PID."],
                ["attribution_method", "sysmon", "Evidence source; 'none' is recorded honestly when unavailable."],
                ["file_sha256", "64 hex characters", "Supports intel matching and later forensic comparison."],
                ["report_path", "...\\reports\\INC-000001-....pdf", "The human-readable incident report for this row."],
            ], [24, 38, 38]),
        ],
    )


def api_doc() -> Document:
    return Document(
        key="api",
        filename="05_API_Documentation.pdf",
        title="API Documentation",
        subtitle="Read-only HTTP JSON API served by scripts/dashboard_server.py.",
        blocks=[
            ("h1", "1. Overview"),
            ("p", "The only network interface is a small read-only HTTP server. It serves the dashboard page, the "
                  "vendored Chart.js bundle and a JSON API over the SQLite evidence store. It is bound to "
                  "127.0.0.1 by default and has no authentication or TLS; it is intended for the lab host."),
            ("code", "python scripts/dashboard_server.py --host 127.0.0.1 --port 8000 \\\n"
                     "    --db-path C:\\RansomwareLab\\canary.db"),
            ("h1", "2. Conventions"),
            ("bullets", [
                "Responses are JSON unless a download is requested; errors are plain HTTP with a status code.",
                "Timestamps are UTC ISO-8601 strings; severity is the display name, severity_rank the numeric order.",
                "Query parameters are validated and clamped to their documented range.",
                "Only /, /index.html and /vendor/* are served statically; every other path returns 404.",
            ]),
            ("h1", "3. Endpoints"),
            ("table", ["Route", "Parameters", "Returns"], API_ROWS, [26, 34, 40]),
            ("h1", "4. Examples"),
            ("h3", "Health"),
            ("code", "GET /api/health\n\n{\n  \"ok\": true,\n  \"version\": \"2.0.0\",\n"
                     "  \"database\": \"/data/lab/canary.db\",\n  \"engine_alive\": true,\n"
                     "  \"engine\": { \"last_heartbeat\": \"2026-11-14T01:10:52Z\",\n"
                     "              \"heartbeat_age_seconds\": 1.4, \"alive\": true }\n}"),
            ("h3", "Findings"),
            ("code", "GET /api/findings?severity=Critical&limit=2\n\n{\n  \"items\": [\n"
                     "    { \"id\": 3, \"occurred_at\": \"2026-11-14T01:04:33Z\",\n"
                     "      \"severity\": \"Critical\", \"severity_rank\": 4,\n"
                     "      \"rule\": \"canary\", \"path\": \"C:\\\\RansomwareLab\\\\testdata\\\\_canary_03.txt\",\n"
                     "      \"pid\": 12588, \"attribution_method\": \"sysmon\",\n"
                     "      \"process\": { \"name\": \"python.exe\", \"username\": \"LAPTOP\\\\Abhishek\" } }\n"
                     "  ],\n  \"total\": 3,\n  \"limit\": 2,\n  \"offset\": 0,\n  \"has_more\": true\n}"),
            ("h3", "Export"),
            ("code", "GET /api/export?format=csv&severity=Critical\n"
                     "Content-Type: text/csv; charset=utf-8\n"
                     "Content-Disposition: attachment; filename=repo-canary-findings-<stamp>.csv"),
            ("p", "CSV output carries a UTF-8 BOM so Excel opens it correctly, quotes every field, and neutralises "
                  "leading =, +, - and @ characters to prevent formula injection. JSONL is one finding per line, "
                  "encoded as UTF-8, and both formats are bounded at 10 000 rows."),
            ("h1", "5. Error behaviour"),
            ("table", ["Situation", "Response"], [
                ["Unknown path", "404, no file contents are ever returned."],
                ["Unknown export format", "200 with CSV (documented fallback)."],
                ["Database not created yet", "200 with an empty result set."],
                ["Engine stopped", "200 with engine_alive=false and a stale heartbeat."],
            ], [40, 60]),
            ("h1", "6. Compatibility"),
            ("p", "GET /findings.json remains as a deprecated alias for external scripts: it returns the 50 most "
                  "recent findings as time, summary and severity. New integrations should use /api/findings."),
        ],
    )


def testing_doc() -> Document:
    return Document(
        key="testing",
        filename="04_Testing_Report.pdf",
        title="Testing Report",
        subtitle="67 automated tests, canary integrity, negative control, live Sysmon verification and Docker run.",
        blocks=[
            ("h1", "1. Strategy"),
            ("p", "Testing is layered. Unit tests exercise the rules, the schema and the parsers without a real "
                  "filesystem. Integration tests start the real engine against a disposable folder. End-to-end "
                  "tests run a full simulated attack and inspect the resulting rows and PDFs. Interface tests call "
                  "the HTTP API. Manual capture in the lab VM records Sysmon evidence. Every claim in this report "
                  "comes from a command whose output was inspected."),
            ("h2", "1.1 What this report proves"),
            ("bullets", [
                "The rules fire once per operation, not once per duplicate delivery: debounce, rolling window and cooldown are tested directly.",
                "The SQLite store is idempotent: the same dedupe_key cannot create a second row.",
                "The canary baseline survives restarts and does not duplicate a live watchdog alert.",
                "The negative control stays silent on ordinary activity, so the detector is not simply 'alert on everything'.",
                "The API is paginated, filtered and read-only; source files return 404.",
                "The simulator cannot leave a marked lab and skips symlinks and oversized files.",
            ]),
            ("h1", "2. Environment"),
            ("table", ["Item", "Value"], [
                ["Operating system", "Windows 11, Python 3.13 virtual environment (image uses 3.12)"],
                ["Runtime dependencies", "watchdog 6.0.0, psutil 7.2.2, fpdf2 2.9.0"],
                ["Sysmon", "15.22, config Sysmon/sysmonconfig.xml"],
                ["Container", "Docker 28.5.2, Compose 2.40.3, buildx 0.29.1"],
                ["Dashboard", "127.0.0.1:8000, SQLite evidence store"],
            ], [30, 70]),
            ("h1", "3. Automated tests"),
            ("p", "pytest collects 67 tests across eight modules. The table lists what each module protects."),
            ("table", ["Module", "Tests", "Coverage"], TEST_ROWS, [26, 8, 66]),
            ("h2", "3.1 Test matrix by requirement"),
            ("table", ["Requirement area", "Tests", "Evidence"], [
                ["FR-1 detection rules", "test_detection_rules.py (14)", "canary, mass change, debounce, cooldown, rename semantics"],
                ["FR-2 evidence store", "test_database.py (11)", "schema, dedupe, enrichment, filters, pagination, migration, heartbeat"],
                ["FR-3 attribution", "test_attribution.py (9)", "XML parsing, path/time matching, retry budget, honest none"],
                ["FR-4 threat intel", "test_threat_intel.py (6)", "feed parsing, streaming hash, cache, size cap, reload"],
                ["FR-5 reporting", "test_reporting.py (4)", "PDF render, throttle, coalescing, queue shutdown"],
                ["FR-6 dashboard/API", "test_dashboard_api.py (8)", "routes, filters, pagination, exports, 404 policy"],
                ["FR-7 Docker", "container smoke", "build, healthcheck, API, source-file 404, data survival"],
                ["FR-8 simulator guardrails", "test_lab_guardrails.py (5)", "marker, dry run, .txt allowlist, symlinks, reset"],
                ["FR-9 canary integrity", "test_canary_integrity.py (10)", "baseline, scan states, seeding, dedupe, schema upgrade"],
            ], [24, 30, 46]),
            ("h1", "4. Negative control"),
            ("p", "scripts/negative_control_test.py seeds the three canaries, performs three creates, one append, "
                  "one rename and one delete in the lab, and asserts that no finding was written. Seeding the "
                  "canaries is what separates the FR-1.4 check from the startup integrity scan: without them the "
                  "engine would correctly report three missing files."),
            ("code", "$ python scripts/negative_control_test.py\n"
                     "Activity:   3 creates, 1 append, 1 rename, 1 delete\n"
                     "Expectation: no alert\nAlerts:     0\n"
                     "[PASS] Normal activity produced no alert (no false positive)."),
            ("h1", "5. End-to-end drill"),
            ("p", "The simulator reverses and renames every .txt file in the marked lab. The engine produced three "
                  "Critical canary findings and one High mass-change finding, wrote four PDF incident reports, "
                  "kept the heartbeat current and left no tracebacks in the log."),
            ("h2", "5.1 Reproducing the drill"),
            ("code", "python scripts\\reset_lab.py --yes --clear-findings\n"
                     "python scripts\\detection_engine.py        # terminal 1\n"
                     "python scripts\\dashboard_server.py       # terminal 2\n"
                     "python simulate_ransomware.py --yes       # terminal 3"),
            ("p", "Expected: three Critical canary findings, at least one High mass-change finding, four PDF reports "
                  "for the four findings (subject to the 12/minute throttle), and the same rows in the dashboard "
                  "within about two seconds. The engine's startup line should say Baseline: 3 stored; startup scan "
                  "0 problem(s)."),
            ("h1", "6. Live Sysmon verification"),
            ("p", "With Sysmon 15.22 installed and the lab configuration applied, a drill run through the engine "
                  "attributed every finding to the simulator process:"),
            ("code", "id=1 canary  Critical pid=20656 method=sysmon process=python.exe path=...\\_canary_01.txt\n"
                     "id=2 canary  Critical pid=20656 method=sysmon process=python.exe path=...\\_canary_02.txt\n"
                     "id=3 canary  Critical pid=20656 method=sysmon process=python.exe path=...\\_canary_03.txt\n"
                     "id=4 mass_change High  pid=20656 method=sysmon process=python.exe path=...\\file15.txt"),
            ("p", "A second run on the same database reached 8/8 attributed rows with two distinct PIDs, which "
                  "shows the correlation is per event rather than a cached value."),
            ("h2", "6.1 Defects found by testing live"),
            ("num", [
                "Attribution raced Sysmon: a single lookup always missed, because watchdog sees the write before "
                "Sysmon writes its record. Fixed with a bounded re-read (three attempts, 0.4 s apart).",
                "The Sysmon config's empty exclude rule matched nothing and logged every process event, drowning "
                "Event ID 11. Fixed with an always-true image condition; the newest records are now file events only.",
                "available() reported 'sysmon' when the channel existed but could not be read, so a non-elevated "
                "engine promised attribution it could not deliver. It now probes one record and reports 'none'.",
            ]),
            ("h2", "6.2 Canary integrity verification"),
            ("p", "The integrity suite covers baseline capture, the missing/modified/touched/replaced/oversized/"
                  "unreadable states, canonical seeding, startup versus periodic scan kinds, duplicate suppression "
                  "and the additive schema upgrade. A restart drill modified a canary while the engine was stopped "
                  "and produced exactly one Critical finding with event type startup_scan; six seconds of "
                  "periodic scans produced no duplicate, and a live watchdog alert suppressed the matching scan "
                  "finding."),
            ("code", "Canary file modified during the startup integrity scan: ...\\_canary_01.txt\n"
                     "severity=Critical  rule=canary  event_type=startup_scan  count=1"),
            ("h1", "7. Interface tests"),
            ("p", "The API suite runs the real server against a temporary database and checks every route, the "
                  "filters, pagination boundaries, both export formats, the legacy alias, and that source files "
                  "return 404. The browser page is checked for the vendored chart bundle and the API paths it uses."),
            ("h1", "8. Packaging verification"),
            ("p", "The Docker image built in 22 steps and produced a 188 MB image. The compose stack started with a "
                  "healthy dashboard; 65 runtime and API checks passed inside the containers, findings survived a "
                  "restart, and the CSV/JSONL exports matched the reported total."),
            ("h2", "8.1 CI gate"),
            ("p", "The GitHub Actions workflow runs three jobs: tests on Windows for Python 3.12 and 3.13, a "
                  "documentation build that validates the eight PDFs, and a Linux container job that builds the "
                  "image, starts the compose stack, runs the simulator and executes tests/ci_container_smoke.py. "
                  "A fresh clone is the point: the CRLF entrypoint failure mode is pinned by .gitattributes and by "
                  "the container smoke test."),
            ("h1", "9. Remaining gaps"),
            ("bullets", [
                "No long-duration false-positive measurement beyond the negative control.",
                "No load test of the enrichment queue under a sustained multi-thousand-file burst.",
                "Attribution verified on one host with one Sysmon version.",
                "A Windows bind mount instead of the named volume was not exercised for inotify propagation.",
                "The integrity baseline covers the three canaries only; mass-change activity during downtime cannot be reconstructed.",
            ]),
            ("h1", "10. Verdict"),
            ("table", ["Claim", "Result", "How it was checked"], [
                ["Automated suite", "67 passed", "pytest -q on the current tree"],
                ["False positives on ordinary work", "0 alerts", "negative control with the canaries present"],
                ["Canary and mass-change demo", "3 Critical + 1 High", "real engine + simulator in a temp lab"],
                ["PDF reports", "4 valid %PDF files", "one per finding, report_path populated"],
                ["Restart continuity", "1 startup_scan finding", "canary changed while stopped; no periodic duplicate"],
                ["Sysmon attribution", "8/8 live rows", "python.exe, correct PID and user across two runs"],
                ["Docker stack", "healthy + 65/65 checks", "compose up, drill, API/export/404 checks"],
            ], [30, 24, 46]),
        ],
    )


def manual() -> Document:
    return Document(
        key="manual",
        filename="05_User_Manual.pdf",
        title="User Manual",
        subtitle="Running drills, reading findings and operating the dashboard.",
        blocks=[
            ("h1", "1. Before you start"),
            ("p", "The lab is disposable by design. Repo-Canary watches C:\\RansomwareLab\\testdata and never "
                  "touches anything outside a folder that contains the .repo-canary-lab marker. Do not point it at "
                  "a real documents folder."),
            ("bullets", [
                "Python 3.12 or newer, plus the requirements installed in a virtual environment.",
                "Optional but recommended: Sysmon 15 with Sysmon/sysmonconfig.xml applied.",
                "The dashboard needs nothing but a browser.",
            ]),
            ("h2", "1.1 Install once"),
            ("code", "python -m venv .venv\n.venv\\Scripts\\activate\npip install -r requirements-dev.txt"),
            ("p", "Requirements-dev installs watchdog, psutil, fpdf2 and pytest. If you only run the system, "
                  "requirements.txt is enough; the dev file is what the verification commands use."),
            ("h1", "2. Start the engine"),
            ("code", "python scripts\\reset_lab.py --yes\n"
                     "python scripts\\detection_engine.py\n\n"
                     "Watching:    C:\\RansomwareLab\\testdata\n"
                     "Database:    C:\\RansomwareLab\\canary.db\n"
                     "Attribution: sysmon\n"
                     "Baseline:    3 stored; startup scan 0 problem(s)\n"
                     "Integrity:   every 300s\nStatus: WATCHING"),
            ("p", "The banner states the watched folder, the database, the report folder, the number of hashes "
                  "loaded and the attribution method. If it says 'none' while you expected 'sysmon', see the "
                  "troubleshooting section."),
            ("h2", "2.1 What each banner field means"),
            ("table", ["Field", "Meaning"], [
                ["Watching", "The exact folder that watchdog will observe recursively."],
                ["Database", "The SQLite file used by both engine and dashboard; pass the same --db-path to both."],
                ["Reports", "Where INC-*.pdf files are written, or 'disabled' when --no-reports is set."],
                ["Threat feed", "The local SHA-256 file and how many valid hashes were loaded."],
                ["Attribution", "sysmon when the channel is readable; none when it is missing or denied (never a guess)."],
                ["Baseline", "How many canary baselines are stored and how many startup-scan problems were found."],
                ["Integrity", "The periodic scan interval; 0 means startup scan only."],
            ], [26, 74]),
            ("h1", "3. Start the dashboard"),
            ("code", "python scripts\\dashboard_server.py\n# open http://127.0.0.1:8000/"),
            ("p", "The page refreshes every two seconds. The header shows total, confirmed, critical and high "
                  "counts; a card shows the latest detection and whether the engine heartbeat is current."),
            ("h2", "3.1 Dashboard tour"),
            ("table", ["Area", "What to look at"], [
                ["Header status", "Connected / engine live or a warning that the heartbeat is stale."],
                ["Counter cards", "Total, Confirmed Ransomware, Critical and High counts for the selected window."],
                ["Latest detection", "The newest row, its severity summary and time."],
                ["Events chart", "Per-minute created/modified/deleted/moved volume, fed by event_counters."],
                ["Process heatmap", "Findings by process and hour; empty when attribution is 'none'."],
                ["Findings table", "Server-side filters, pagination, severity/rule, process and report link."],
                ["Export buttons", "CSV (Excel-friendly, BOM) or JSONL (one object per line)."],
            ], [26, 74]),
            ("h1", "4. Run a drill"),
            ("code", "python simulate_ransomware.py --dry-run   # list what would change\n"
                     "python simulate_ransomware.py             # reverse and rename in the lab"),
            ("p", "The simulator refuses to run if the folder is not a marked lab, only touches .txt files, skips "
                  "symlinks and files above 10 MB, and asks for confirmation unless --yes is given. It prints each "
                  "file it touches so you can match the output to the dashboard."),
            ("h2", "4.1 Safety rules the simulator enforces"),
            ("bullets", [
                "The target folder must contain .repo-canary-lab; a mis-set REPO_CANARY_TEST_DIR aborts instead of touching real files.",
                "Only regular .txt files are processed; binaries, directories and symlinks are skipped.",
                "Files above 10 MiB are skipped, and --dry-run lists the plan without writing.",
                "It reverses text and renames to .locked; it does not encrypt, delete or exfiltrate anything.",
                "--yes is required for an unattended run; without it the operator confirms interactively.",
            ]),
            ("h1", "5. Read the findings"),
            ("bullets", [
                "Critical - a canary file was touched.",
                "High - a mass change was detected (ten or more events in ten seconds).",
                "Confirmed Ransomware - the file hash matched the local threat-intel feed.",
                "Attribution - the process name, PID and user, or 'none' when Sysmon could not supply them.",
            ]),
            ("p", "Use the severity filter, the rule filter and the search box to narrow the table; the page "
                  "fetches only the rows it displays. 'Export CSV' produces an Excel-friendly file, 'Export JSONL' "
                  "produces one JSON object per line for scripts."),
            ("h2", "5.1 Reading a finding row"),
            ("table", ["Column", "How to read it"], [
                ["Time", "UTC ISO-8601; compare directly with Sysmon UtcTime."],
                ["Severity", "Confirmed Ransomware (5) > Critical (4) > High (3) > Medium (2) > Low (1) > Info (0)."],
                ["Rule", "canary, mass_change or hash_match. trigger_rule preserves the rule that fired first."],
                ["File", "The exact path; a rename may show the source path that triggered the finding."],
                ["Process", "Name, PID, executable, command line and user, or 'unattributed' with method 'none'."],
                ["Hash / intel", "SHA-256 and the feed label when a known sample matched."],
                ["Report", "Click through to the INC-*.pdf for the human-readable incident record."],
            ], [24, 76]),
            ("h1", "6. Incident reports"),
            ("p", "Each alert writes a PDF into C:\\RansomwareLab\\reports and links it from the finding. Reports "
                  "are throttled to twelve per minute and coalesced per rule and path, so a burst produces a "
                  "handful of reports rather than hundreds."),
            ("h2", "6.1 What is inside a report"),
            ("bullets", [
                "Report ID, generation time, hostname and engine version.",
                "Occurred time, severity, rule, trigger rule and the exact summary.",
                "File path, SHA-256, intel label and matched hash.",
                "Attribution method, PID, process name, executable, user and command line.",
                "If the report was throttled, the finding row still exists; only the separate PDF was coalesced.",
            ]),
            ("h1", "7. Reset the lab"),
            ("code", "python scripts\\reset_lab.py --yes                 # restore the disposable files\n"
                     "python scripts\\reset_lab.py --yes --clear-findings  # also empty the evidence table"),
            ("h1", "8. Canary integrity and restarts"),
            ("p", "reset_lab.py stores a SHA-256/size/mtime baseline for the three canaries. The engine checks "
                  "that baseline before watchdog starts and then every --integrity-interval seconds. This is what "
                  "catches a canary that was changed, renamed or deleted while the engine was stopped. A startup "
                  "or periodic scan finding uses the normal canary rule and records event type startup_scan or "
                  "integrity_scan; a live watchdog alert for the same canary suppresses the duplicate scan row."),
            ("code", "python scripts\\detection_engine.py --integrity-interval 60\n"
                     "python scripts\\detection_engine.py --integrity-interval 0   # startup scan only"),
            ("h1", "9. Troubleshooting"),
            ("table", ["Symptom", "Cause and fix"], [
                ["Banner says 'Attribution: none'", "Sysmon is not installed, or the account cannot read the channel. Install it, or run elevated / join Event Log Readers."],
                ["Dashboard is empty", "The engine has not written yet, or --db-path differs from the server's."],
                ["Startup scan reports a missing canary", "The lab was not reset, or the canary was changed while the engine was stopped. Run reset_lab.py --yes to restore the baseline."],
                ["Integrity scan repeats an alert", "A live watchdog alert should suppress the scan duplicate. Check that only one engine is writing to the database and that the baseline was captured by reset_lab.py."],
                ["No alerts from the simulator", "The marker file is missing. Run reset_lab.py --yes in the watched folder."],
                ["Mass-change alerts fire during a drill", "Expected: the drill writes many files quickly; the finding is deduplicated."],
                ["CSV opens with odd characters", "Use the BOM-prefixed export the dashboard produces; it targets Excel."],
            ], [32, 68]),
            ("h2", "9.1 Frequently asked questions"),
            ("bullets", [
                "Why does the process column say unattributed? Sysmon is missing or the account cannot read its channel; the engine never guesses.",
                "Why did a burst produce fewer PDFs than findings? The reporter throttles to 12/minute and coalesces the same rule+path within 60 seconds.",
                "Can I run this on real documents? No. Use the marked lab; the simulator refuses to run elsewhere and the engine is designed for a disposable folder.",
                "What happens if I stop the engine and change a canary? The next startup scan reports it with event type startup_scan.",
                "Does the dashboard write anything? No. It opens query_only connections and serves index.html plus vendor assets only.",
            ]),
            ("h1", "10. Command reference"),
            ("table", ["Command", "Purpose"], [
                ["python scripts\\reset_lab.py --yes --clear-findings", "Restore canaries, files, marker and baseline; empty evidence."],
                ["python scripts\\detection_engine.py", "Start the watchdog engine with defaults."],
                ["python scripts\\dashboard_server.py", "Serve the dashboard and read-only API."],
                ["python simulate_ransomware.py --yes", "Run the harmless drill."],
                ["python scripts\\negative_control_test.py", "Prove ordinary activity produces zero findings."],
                ["python -m pytest -q", "Run the 67-test suite."],
                ["python scripts\\detection_engine.py --integrity-interval 60", "Scan canaries every 60 seconds."],
            ], [50, 50]),
        ],
    )


def installation() -> Document:
    return Document(
        key="install",
        filename="08_Installation_Guide.pdf",
        title="Installation Guide",
        subtitle="Native Windows, Docker Compose and Sysmon setup with verification steps.",
        blocks=[
            ("h1", "1. Prerequisites"),
            ("bullets", [
                "Windows 10/11 or a Linux host; Python 3.12+ for a native run.",
                "Administrator access only for installing Sysmon and applying its configuration.",
                "Docker Engine or Docker Desktop for the container route.",
            ]),
            ("h1", "2. Native installation"),
            ("code", "git clone https://github.com/Junkie-008/repo-canary\ncd repo-canary\n"
                     "python -m venv .venv\n.venv\\Scripts\\activate\n"
                     "pip install -r requirements.txt"),
            ("p", "Create the lab once, then start the two processes in separate terminals."),
            ("code", "python scripts\\reset_lab.py --yes\npython scripts\\detection_engine.py\n"
                     "python scripts\\dashboard_server.py"),
            ("h1", "3. Sysmon for attribution"),
            ("p", "Download Sysmon from Sysinternals, then install it with the repository configuration from an "
                  "elevated prompt. The configuration logs FileCreate (Event ID 11) for the lab folders and "
                  "excludes process events so the channel stays readable."),
            ("code", "Sysmon64.exe -accepteula -i Sysmon\\sysmonconfig.xml\n"
                     "Sysmon64.exe -c Sysmon\\sysmonconfig.xml    # re-apply after editing\n"
                     "sc query Sysmon64"),
            ("p", "The engine account must be able to read Microsoft-Windows-Sysmon/Operational. Either run the "
                  "engine elevated or add the account to the Event Log Readers group. When it cannot read the "
                  "channel the engine says so and records attribution_method='none'."),
            ("h1", "4. Container installation"),
            ("code", "docker compose up -d --build\ndocker compose ps\n"
                     "docker compose logs -f engine"),
            ("p", "The compose file builds one image, runs the engine and the dashboard against the canary-data "
                  "volume, and publishes the dashboard on 127.0.0.1:8000 with a healthcheck against /api/health. "
                  "The entrypoint initialises the lab on first start."),
            ("h1", "5. Configuration"),
            ("table", ["Variable", "Default", "Meaning"], ENV_ROWS, [30, 26, 44]),
            ("p", "Engine CLI flags override the environment: --test-dir, --db-path, --attribution "
                  "auto|sysmon|none, --integrity-interval, --report-dir, --no-reports, --hash-file and "
                  "--max-hash-bytes. --integrity-interval defaults to 300 seconds; 0 runs only the startup scan."),
            ("h1", "6. Verification"),
            ("code", "python -m pytest -q                     # expect 67 passed\n"
                     "python scripts\\negative_control_test.py # expect PASS, 0 alerts\n"
                     "curl http://127.0.0.1:8000/api/health    # expect ok:true, engine_alive:true\n"
                     "docker compose ps                         # expect dashboard (healthy)"),
            ("h1", "7. Upgrading from the prototype"),
            ("p", "A findings.json beside the database is migrated automatically on first start and renamed to "
                  "findings.json.migrated. The old --findings flag is still accepted as a deprecated alias and "
                  "maps to a .db path, so existing shortcuts keep working while the runbooks are updated."),
        ],
    )


def readme() -> Document:
    return Document(
        key="readme",
        filename="09_README.pdf",
        title="README",
        subtitle="Project overview, quick start and repository map.",
        blocks=[
            ("h1", "Ransomware 207 - Repo-Canary"),
            ("p", "Incident detection for a ransomware attack on a Windows server. The engine watches a disposable "
                  "lab folder, detects canary tampering and mass file change, attributes the writing process "
                  "through Sysmon Event ID 11, enriches affected files with SHA-256 threat intelligence, writes a "
                  "PDF incident report per alert and exposes everything through a local dashboard."),
            ("h1", "Highlights"),
            ("bullets", [
                "SQLite evidence store with WAL, unique dedupe keys and one-time JSON migration.",
                "Persisted canary baseline with startup and periodic integrity scans, so downtime does not hide tampering.",
                "Honest attribution: Sysmon correlation when available, 'none' when it is not.",
                "Asynchronous enrichment and PDF reporting, so the watchdog thread never blocks.",
                "Paginated JSON API with CSV and JSONL export, feeding a Chart.js dashboard.",
                "Multi-stage Docker image, non-root user, shared volume, healthcheck.",
                "67 automated tests, a negative control and recorded end-to-end evidence.",
            ]),
            ("h1", "Quick start"),
            ("code", "python -m venv .venv && .venv\\Scripts\\activate\npip install -r requirements.txt\n"
                     "python scripts\\reset_lab.py --yes\npython scripts\\detection_engine.py\n"
                     "# second terminal\npython scripts\\dashboard_server.py"),
            ("h1", "Repository map"),
            ("table", ["Path", "Contents"], [
                ["scripts/detection_engine.py", "Engine: observer, rules, persistence, enrichment, heartbeat."],
                ["scripts/detection_rules.py", "Canary and mass-change rules."],
                ["scripts/database.py", "SQLite schema, queries, migration."],
                ["scripts/canary_integrity.py", "Persisted canary baseline, startup/periodic scans, duplicate suppression."],
                ["scripts/attribution.py", "Sysmon Event ID 11 correlation and psutil enrichment."],
                ["scripts/threat_intel.py", "Local SHA-256 feed with cache and reload."],
                ["scripts/reporting.py", "PDF incident reports and throttle."],
                ["scripts/dashboard_server.py", "Read-only HTTP API and static dashboard."],
                ["index.html", "Dashboard UI (vendored Chart.js)."],
                ["simulate_ransomware.py", "Harmless drill inside a marked lab."],
                ["Sysmon/sysmonconfig.xml", "Sysmon configuration for the lab folders."],
                ["tests/", "67 tests across eight modules."],
                ["Dockerfile, docker-compose.yml", "Container packaging."],
            ], [32, 68]),
            ("h1", "Evidence in one place"),
            ("bullets", [
                "Findings live in canary.db; reports are PDFs under reports/.",
                "The dashboard is the fastest way to read them; the API is the scriptable way.",
                "AGENT.md records the design decisions and the verification log.",
            ]),
            ("h1", "Limitations"),
            ("p", "Detection and evidence only: no containment or recovery. The dashboard has no authentication and "
                  "binds to loopback. Threat intelligence matches known hashes only. Attribution requires Sysmon and "
                  "read access to its channel. The canary baseline lives in canary.db, so an administrator who can "
                  "rewrite the database can rewrite the baseline, and the scan covers the three canaries only."),
        ],
    )


def future() -> Document:
    return Document(
        key="future",
        filename="06_Future_Scope.pdf",
        title="Future Scope",
        subtitle="Directions that build on the current evidence pipeline, with the work each one needs.",
        blocks=[
            ("h1", "1. How to read this document"),
            ("p", "The current system is complete for its stated scope: detect, attribute, enrich, report and "
                  "expose evidence on one Windows host. This document lists what could come next, why each item "
                  "matters, what implementing it would involve and how the result could be verified. Nothing here "
                  "is required for the current demonstration; the list is ordered by value-to-effort rather than "
                  "by ambition."),
            ("table", ["Direction", "Problem it solves", "Effort"], [
                ["Alert delivery", "Nobody is watching the dashboard overnight.", "Low"],
                ["Decision-model triage", "An analyst must read every row to judge escalation.", "Medium"],
                ["Authentication and TLS", "The dashboard cannot safely leave loopback.", "Low"],
                ["Retention and volume", "canary.db and reports/ grow without bound.", "Low"],
                ["Behavioural detection", "Rename-after-modify and downtime bursts are invisible.", "Medium"],
                ["Multi-host aggregation", "Each host has its own isolated dashboard.", "High"],
                ["Operational packaging", "The engine needs a logged-in session and manual setup.", "Medium"],
                ["Response actions", "Detection still requires a human to contain the threat.", "High"],
            ], [24, 52, 24]),
            ("h1", "2. Alert delivery"),
            ("p", "Findings currently surface in the dashboard and on disk. Email or webhook delivery for "
                  "Critical and Confirmed Ransomware severities would make the system useful on an unattended "
                  "host. The reporter's existing throttle and coalescing can be reused, so a burst produces one "
                  "notification instead of hundreds."),
            ("bullets", [
                "Build the payload from the persisted row, not from memory, so a notification always matches the evidence.",
                "Make the severity floor configurable (default Critical) and let each destination opt out of lower severities.",
                "Retry with bounded backoff and record delivery success or failure next to the finding.",
                "Verify with a local sink: force a drill, confirm one message per finding, then break the sink and confirm the report still exists.",
            ]),
            ("h1", "3. Decision-model triage"),
            ("p", "Enrichment is the natural place for a triage stage: severity, process reputation, path entropy "
                  "and hash intelligence are already on the row. A decision model could recommend escalation "
                  "without changing the detection path. This was explicitly out of scope in the current pass."),
            ("bullets", [
                "Start with an explainable score over existing fields before considering a trained model; every recommendation must cite its inputs.",
                "Run in shadow mode first: store the recommendation but leave the displayed severity unchanged.",
                "Replay the recorded drills and the negative control to confirm the model does not promote ordinary activity.",
                "Keep the detection rules authoritative, so a triage failure cannot suppress a canary finding.",
            ]),
            ("h1", "4. Authentication and transport security"),
            ("p", "The dashboard is loopback-only and unauthenticated. A token or session login plus TLS would let "
                  "it serve an analyst workstation on the network without exposing evidence to anyone who can "
                  "reach the port. The server stays read-only; only the transport and identity layer change."),
            ("bullets", [
                "Add a login page and an HttpOnly, SameSite session cookie; keep the API read-only behind the same check.",
                "Terminate TLS at the server or a local reverse proxy, and redirect plain HTTP to HTTPS.",
                "Return 401 for missing credentials and 403 for a valid but unauthorised account, with no evidence in either response.",
                "Verify that /api/findings, /api/export and the static page all reject an anonymous request once auth is enabled.",
            ]),
            ("h1", "5. Retention and volume growth"),
            ("p", "Evidence is append-only. A retention policy (age-based, or keep every Critical and prune "
                  "routine mass-change rows) and a scheduled database checkpoint would keep canary.db small on a "
                  "long-running server, while keeping the reports that a responder would actually open."),
            ("bullets", [
                "Never prune Confirmed Ransomware or Critical rows automatically; expire only routine High/Medium/Info rows after a configured age.",
                "Delete or archive the matching PDF when its row is pruned, so the evidence store and the reports directory cannot disagree.",
                "Run a periodic WAL checkpoint and an occasional VACUUM, and log how many rows and files were removed.",
                "Offer a dry run that reports the counts before anything is deleted.",
            ]),
            ("h1", "6. Behavioural detection"),
            ("p", "The current rules are deliberately simple and explainable. Adding entropy sampling or "
                  "content-change ratios would catch a file that is modified and later renamed, which the canary "
                  "and rate rules see only as unrelated events. A filesystem journal could also reconstruct "
                  "mass-change activity during engine downtime; today the persisted baseline covers only the three "
                  "canaries."),
            ("bullets", [
                "Sample the first and last block of a changed file and compare entropy, so the cost stays bounded on large files.",
                "Treat a renamed file whose content changed as one event, not two unrelated ones.",
                "Use the NTFS USN journal to reconstruct activity during downtime, with the same dedupe key discipline as live events.",
                "Add a rename-after-modify case to the rule tests, and prove the negative control still produces zero alerts.",
            ]),
            ("h1", "7. Multi-host aggregation"),
            ("p", "Each host writes its own database. Shipping findings to a central collector would allow one "
                  "dashboard across a fleet; the JSON API and the stable schema make the export straightforward, "
                  "and the dedupe key already prevents duplicates on the collector side."),
            ("bullets", [
                "Add a host_id to the exported record and to the collector schema, keeping the existing dedupe_key unique per host.",
                "Ship JSONL over HTTPS with a per-host credential and a local spool, so a network outage does not lose evidence.",
                "Build the fleet view as another reader of the collector, not as a second detection path.",
                "Verify with two simulated hosts: the same finding sent twice must produce one collector row.",
            ]),
            ("h1", "8. Operational packaging"),
            ("bullets", [
                "A Windows service wrapper so the engine starts before a user logs in and restarts after a crash.",
                "Signed Sysmon and engine configuration, verified at startup.",
                "Structured JSON logging alongside the rotating text log.",
                "A health endpoint that reports queue depth and last enrichment latency.",
                "A documented upgrade path that runs the additive schema migration before the observer starts.",
            ]),
            ("h1", "9. Response actions"),
            ("p", "Containment - suspending a process, quarantining a folder, snapshotting before encryption "
                  "spreads - is the obvious next capability. It needs carefully scoped guardrails, because a "
                  "detector that can also act on a false positive can cause the damage it is meant to prevent."),
            ("bullets", [
                "Ship it disabled by default, with an explicit allowlist of processes and paths that may be acted on.",
                "Require a dry run and a second confirmation for a destructive action, and snapshot before isolating anything.",
                "Write every action to the evidence store with the actor, target, time and outcome.",
                "Replay the negative control and a full drill before enabling it, and keep an immediate rollback path.",
            ]),
            ("h1", "10. Suggested sequence"),
            ("table", ["Phase", "Items", "Exit criterion"], [
                ["1. Operate unattended", "Alert delivery, Windows service wrapper, structured logs", "A drill on an unattended host produces a notification and survives a reboot."],
                ["2. Protect the interface", "Authentication, TLS, retention policy", "Anonymous access is refused and an aged lab shrinks predictably."],
                ["3. Strengthen detection", "Entropy sampling, rename-after-modify, USN journal", "A modify-then-rename case is detected once, and downtime activity is reconstructed."],
                ["4. Scale and act", "Multi-host collector, guard-railed containment", "Two hosts report into one dashboard, and a contained drill is fully audited."],
            ], [22, 40, 38]),
            ("p", "Each phase is independently useful and independently testable. That ordering also keeps the "
                  "project's central promise intact: every claim in the current report remains true until a new "
                  "phase is verified, and nothing is added to the detection path without evidence that it works."),
        ],
    )


def synopsis() -> Document:
    return Document(
        key="synopsis",
        filename="07_Synopsis.pdf",
        title="Synopsis",
        subtitle="Project synopsis: problem, approach, implementation and outcomes.",
        blocks=[
            ("h1", "1. Title"),
            ("p", "Incident Detection for a Ransomware Attack on a Windows Server (project RANSOMWARE 207, "
                  "repository Repo-Canary)."),
            ("h1", "2. Introduction"),
            ("p", "Ransomware attacks succeed because encryption is fast and the defender's evidence is slow. By "
                  "the time an analyst opens a console, thousands of files may already be rewritten. The project "
                  "builds a detection layer that produces trustworthy evidence within seconds: which file changed, "
                  "how large the burst was, which process did it, whether the file matches known ransomware, and a "
                  "report that records all of it."),
            ("h2", "2.1 The project in one minute"),
            ("num", [
                "A disposable folder holds three canary files and ordinary test documents, all inside a marked lab.",
                "The engine watches that folder with watchdog and checks every event against two simple rules: a canary was touched, or ten files changed in ten seconds.",
                "The moment a rule fires, the finding is written to SQLite with its time, severity, path and a deduplication key.",
                "A worker then asks Sysmon which process wrote the file, expands the PID with psutil, hashes the file and checks a local list of known ransomware hashes.",
                "A PDF incident report is rendered on a separate thread, and its path is attached to the same finding.",
                "The dashboard reads the same database and shows the finding, the per-minute event chart, the process heatmap and the export buttons.",
                "At startup and on an interval, the engine also compares each canary with a stored baseline, so tampering during downtime is still reported.",
            ]),
            ("p", "That is the whole project: observation, an explainable decision, durable evidence, honest attribution, "
                  "a human-readable report and a live view. Every later section explains one of those steps in more detail."),
            ("h1", "3. Problem statement"),
            ("bullets", [
                "File-integrity tools report changes but cannot say which process made them.",
                "Signature scanners miss new samples and say nothing about a write in progress.",
                "Prototype implementations store evidence in flat files that truncate and corrupt.",
                "Without process attribution, an alert cannot become a response action.",
            ]),
            ("h1", "4. Objectives"),
            ("num", [
                "Detect canary tampering and mass file modification in real time.",
                "Attribute the write to a process using kernel evidence, or state honestly that it cannot.",
                "Persist evidence in a concurrent store that survives restarts.",
                "Enrich with SHA-256 hashes and local threat intelligence.",
                "Generate a PDF incident report per alert without stalling detection.",
                "Expose findings through a paginated API and a live dashboard.",
                "Package and verify the system for reproducible deployment.",
            ]),
            ("h1", "5. Methodology"),
            ("p", "The work followed an evidence-first loop: observe with watchdog, decide with explicit rules, "
                  "persist before enriching, and verify every claim with a command whose output was inspected. "
                  "Each stage was tested in isolation and then end to end against a disposable lab that the "
                  "simulator attacks harmlessly."),
            ("table", ["Stage", "Technology", "Output"], [
                ["Observation", "watchdog 6.0", "File events for the watched folder."],
                ["Rules", "Python", "Canary (Critical) and mass-change (High) findings."],
                ["Evidence", "SQLite (WAL)", "findings, processes, hashes, canary baseline, counters, heartbeat."],
                ["Continuity", "Persisted canary baseline", "Startup and periodic scans catch changes made during downtime."],
                ["Attribution", "Sysmon Event ID 11 + psutil", "PID, image, command line, user, or 'none'."],
                ["Intelligence", "Local SHA-256 feed", "Confirmed Ransomware on a match."],
                ["Reporting", "fpdf2", "One PDF incident report per alert."],
                ["Interface", "http.server + Chart.js", "Paginated JSON API and dashboard."],
                ["Packaging", "Docker, Compose", "Non-root image, shared volume, healthcheck."],
            ], [18, 32, 50]),
            ("h1", "6. Implementation summary"),
            ("p", "The engine watches the lab folder and inserts a finding the moment a rule fires. Enrichment runs "
                  "on a worker thread: Sysmon Event ID 11 records are correlated by path and time (with a bounded "
                  "re-read because watchdog is faster than Sysmon), the PID is expanded with psutil, the file is "
                  "hashed and checked against the feed, and a PDF is queued. The dashboard reads the same SQLite "
                  "database through WAL, so it never blocks the writer. A persisted canary baseline is verified "
                  "before the observer starts and on an interval, so a canary changed while the service was down "
                  "is still reported once the engine returns."),
            ("p", "Attribution was verified against a live Sysmon 15.22 installation: every canary and mass-change "
                  "finding in the drill was attributed to the simulator process, with the correct PID and user, "
                  "across two runs and two distinct PIDs."),
            ("h2", "6.1 What happens when a canary is touched"),
            ("num", [
                "The simulator renames _canary_01.txt; watchdog delivers a moved event with the source path.",
                "The rule engine recognises the canary name, debounces duplicate deliveries and creates a Critical finding.",
                "The row is committed before any slow work, so a Sysmon delay or a PDF failure cannot lose the alert.",
                "The worker correlates Sysmon Event ID 11 within a three-second window, retrying up to three times because watchdog is faster than Sysmon.",
                "The process dimensions (image, command line, user) are stored once and referenced by the finding.",
                "The file is hashed and compared with the local feed; a match would upgrade the row to Confirmed Ransomware.",
                "A PDF report is queued, rendered and linked from report_path.",
                "The dashboard's next two-second poll displays the row, and /api/findings returns the same evidence to a script.",
            ]),
            ("h1", "7. Results"),
            ("table", ["Check", "Result"], [
                ["Automated suite", "67 tests passed."],
                ["Negative control", "PASS - three creates, one append, one rename, one delete produced zero alerts."],
                ["End-to-end drill", "3 Critical canary + 1 High mass-change findings, 4 PDF reports, no tracebacks."],
                ["Restart integrity", "A canary changed while stopped produced exactly one Critical startup_scan finding; periodic scans did not duplicate it."],
                ["Live Sysmon attribution", "8/8 findings attributed to python.exe (method sysmon)."],
                ["Docker build and compose", "22-step build, 188 MB image, healthy stack, 65/65 checks, data survived restart."],
            ], [30, 70]),
            ("h1", "8. Limitations"),
            ("bullets", [
                "Detection only: no containment, quarantine or recovery.",
                "Attribution requires Sysmon and read access to its channel.",
                "Threat intelligence matches known SHA-256 samples only.",
                "The dashboard is loopback-only, without authentication or TLS.",
                "Containers have no Sysmon, so attribution there is 'none' by design.",
                "The canary baseline is stored in the same database it protects, and the scan covers canaries only; mass-change during downtime is not reconstructed.",
            ]),
            ("h1", "9. Future work"),
            ("p", "Alert delivery, decision-model triage on the enriched row, authentication and TLS, retention "
                  "policies, entropy-based detection and multi-host aggregation are the natural next steps. "
                  "Containment actions would follow once false-positive behaviour is characterised over a longer "
                  "period."),
            ("h1", "10. Conclusion"),
            ("p", "The project delivers a defensible detection pipeline: explainable rules, a durable evidence "
                  "store, real process attribution with an honest fallback, restart-proof canary integrity checks, "
                  "incident reports and a dashboard, all reproducible on another machine and backed by a 67-test "
                  "suite."),
            ("h1", "11. Glossary"),
            ("table", ["Term", "Plain-language meaning"], [
                ["Canary file", "A disposable file that exists only to be touched; touching it is the alarm."],
                ["Mass change", "Ten or more file events inside ten seconds, the signature of a fast encryptor."],
                ["Finding", "One alert saved in the database with its time, severity, path and evidence."],
                ["Attribution", "Working out which process wrote the file, using Sysmon rather than a guess."],
                ["Honest fallback", "Storing 'none' when attribution is unavailable instead of inventing a PID."],
                ["Enrichment", "Asynchronous work that adds process, hash and threat-intel fields to a saved finding."],
                ["Canary baseline", "The expected SHA-256, size and timestamp of a canary, used to detect downtime tampering."],
                ["Dedupe key", "A unique fingerprint that makes repeated ingestion of the same alert idempotent."],
                ["WAL", "SQLite's write-ahead log, which lets the dashboard read while the engine writes."],
            ], [24, 76]),
            ("h1", "12. References"),
            ("bullets", [
                "Microsoft Sysinternals, Sysmon v15 documentation and event schema.",
                "watchdog, psutil and fpdf2 project documentation.",
                "SQLite documentation: WAL mode, busy timeout, upsert semantics.",
                "Docker documentation: multi-stage builds and named volumes.",
                "MITRE ATT&CK, T1486 Data Encrypted for Impact.",
            ]),
        ],
    )


def deck() -> Document:
    slides = [
        ("Incident Detection for a Ransomware Attack on a Windows Server",
         ["Project RANSOMWARE 207 | Group G3", "Abhishek (2400320100046)", "Guide: SarathG | Session 2026-27"]),
        ("The Problem",
         ["Encryption completes in seconds; evidence arrives minutes later.",
          "File-integrity tools report a change but not the process behind it.",
          "Signature scanners miss new samples and see nothing mid-write.",
          "Prototypes store evidence in flat files that truncate and corrupt."]),
        ("Objectives",
         ["Detect canary tampering and mass file change in real time.",
          "Attribute each write to a process, or state honestly that we cannot.",
          "Persist evidence in a concurrent, queryable store.",
          "Enrich with hashes and local threat intelligence.",
          "Report and expose the evidence without slowing detection."]),
        ("System Architecture",
         ["watchdog Observer -> rule engine -> SQLite evidence store.",
          "Integrity monitor verifies a persisted canary baseline at startup and on an interval.",
          "Enrichment worker: Sysmon Event ID 11, SHA-256, PDF report.",
          "Dashboard server reads the same database through WAL.",
          "Simulator plays the attacker inside a marked lab."]),
        ("Detection Rules",
         ["Canary: any touch of three disposable files -> Critical.",
          "Mass change: 10 events in 10 s -> High, debounced at 0.5 s.",
          "Hash match against the local feed -> Confirmed Ransomware.",
          "Renames counted once, destination still canary-checked.",
          "Startup and periodic scans catch changes made while the engine was stopped."]),
        ("Restart Continuity",
         ["reset_lab stores SHA-256, size and mtime for each canary in SQLite.",
          "Startup scan runs before the observer; periodic scan runs every 300 s by default.",
          "Missing/modified/touched/replaced/oversized canary -> Critical finding.",
          "A live watchdog alert suppresses the duplicate scan row, but a new state still escalates."]),
        ("Evidence Store: SQLite",
         ["Tables: findings, processes, known_hashes, canary_baseline, event_counters, engine_state.",
          "WAL mode, per-operation connections, busy timeout.",
          "UNIQUE dedupe_key with ON CONFLICT DO NOTHING - never INSERT OR REPLACE.",
          "Legacy findings.json migrated once, then renamed .migrated."]),
        ("Process Attribution",
         ["watchdog gives a path, not a PID; psutil cannot attribute a write.",
          "Sysmon Event ID 11 carries the PID; correlate by path and time.",
          "Three-second window, bounded re-read for Sysmon's write lag.",
          "No evidence -> attribution_method='none', never a guess."]),
        ("Sysmon Evidence",
         ["Sysmon 15.22 installed with the repo configuration.",
          "Canary + mass-change drill: 8/8 findings attributed to python.exe.",
          "Correct PID and user across two runs and two distinct PIDs.",
          "Non-elevated engine reports 'none' with an actionable warning."]),
        ("Threat Intelligence",
         ["Local SHA-256 feed, offline by design.",
          "Streamed hashing with a 256 MiB cap.",
          "LRU cache plus reload when the feed changes.",
          "Match upgrades the finding to Confirmed Ransomware."]),
        ("Incident Reports",
         ["One PDF per alert, rendered with fpdf2.",
          "Async worker: detection never waits for a PDF.",
          "Throttled to 12/min, coalesced per rule and path.",
          "Report path stored on the finding."]),
        ("Dashboard and API",
         ["Paginated, server-side filters: severity, rule, text, time.",
          "Events-per-minute chart and process heatmap (vendored Chart.js).",
          "CSV (UTF-8 BOM) and JSONL export.",
          "/api/health reports the engine heartbeat."]),
        ("Packaging",
         ["Multi-stage python:3.12-slim image, offline wheelhouse.",
          "Non-root uid 10001, shared canary-data volume.",
          "Compose runs engine + dashboard, healthcheck on /api/health.",
          "188 MB image; stack verified end to end."]),
        ("Testing",
         ["67 automated tests across eight modules.",
          "Negative control: 6 normal operations, zero alerts.",
          "End-to-end drill: 3 Critical + 1 High, 4 PDF reports.",
          "Docker: 65/65 runtime and API checks, data survived a restart."]),
        ("Defects Found by Testing Live",
         ["Attribution raced Sysmon: added a bounded re-read.",
          "Sysmon exclude rule matched nothing: process events flooded the channel.",
          "available() claimed sysmon while the channel was unreadable."]),
        ("Limitations",
         ["Detection only - no containment or recovery.",
          "Attribution needs Sysmon and read access to its channel.",
          "Hash intelligence only; no zero-day coverage.",
          "Loopback-only dashboard without auth or TLS."]),
        ("Future Scope",
         ["Alert delivery and decision-model triage on enriched rows.",
          "Authentication, TLS and retention policies.",
          "Entropy-based detection and multi-host aggregation.",
          "Guard-railed containment once false positives are characterised."]),
        ("Conclusion",
         ["Explainable rules, durable evidence, honest attribution.",
          "Reports and a dashboard a responder can act on.",
          "Reproducible on another machine; 67 tests backing every claim."]),
    ]

    return Document(
        key="deck",
        filename="08_Project_Presentation.pdf",
        title="Project Presentation",
        subtitle="Slide deck.",
        landscape=True,
        blocks=[("slide", title, bullets) for title, bullets in slides],
    )


DOCUMENTS = [
    architecture(),
    diagrams(),
    database_doc(),
    testing_doc(),
    manual(),
    future(),
    synopsis(),
    deck(),
]

MARKDOWN_FILES = {
    "readme": "README.md",
    "install": "INSTALLATION_GUIDE.md",
    "database": "DATABASE_SCHEMA.md",
    "api": "API_DOCUMENTATION.md",
}
