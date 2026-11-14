"""Content for the Ransomware 207 documentation set.

Every document is defined once as a list of blocks and rendered to PDF (and,
where useful, Markdown) by ``docs_builder``. Facts below are taken from the
current Repo-Canary tree: SQLite storage, Sysmon Event ID 11 attribution,
fpdf2 incident reports, the Docker packaging and the 57-test suite.
"""

from __future__ import annotations

from docs_builder import Document

VERSION = "2.0.0"

SCHEMA_ROWS = [
    ["schema_meta", "key TEXT PK, value TEXT", "Schema version and one-off migration flags."],
    ["processes", "id, name, exe_path, cmdline, username, first_seen, last_seen", "Normalised process dimension shared by findings; UNIQUE(name, exe_path, cmdline)."],
    ["known_hashes", "sha256 PK CHECK(length=64), label, source, added_at", "Mirror of the local SHA-256 threat-intel feed."],
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
]

NFR_ROWS = [
    ["NFR-1", "Detection latency: a canary write must produce a stored finding within one second."],
    ["NFR-2", "Concurrency: the dashboard must read while the engine writes, with no 'database is locked'."],
    ["NFR-3", "Portability: Windows first, Linux container supported, paths configurable by environment."],
    ["NFR-4", "Offline operation: no internet access at runtime; Chart.js is vendored."],
    ["NFR-5", "Auditability: every alert keeps time, path, rule, severity, process and hash evidence."],
    ["NFR-6", "Safety: the simulator touches only .txt files in a marked lab and never follows symlinks."],
    ["NFR-7", "Observability: heartbeat, rotating log, and a non-zero exit when the observer dies."],
    ["NFR-8", "Maintainability: 57 automated tests and no hidden global state."],
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
                  "PDF incident report while a dashboard shows the live picture."),
            ("p", "This version is a production-grade refactor of the original prototype. The prototype kept "
                  f"findings in a flat findings.json capped at 50 entries and could not say which process wrote "
                  f"a file. The current system (version {VERSION}) stores evidence in SQLite, attributes writes "
                  "through Sysmon Event ID 11 with an explicit honest fallback, generates PDF incident reports "
                  "asynchronously, serves a paginated JSON API feeding a Chart.js dashboard, and ships as a "
                  "non-root Docker image that was built and exercised end to end."),
            ("h1", "2. Objectives"),
            ("num", [
                "Detect tampering with three canary files and mass file modification inside the lab folder.",
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
                     "dashboard  <- GET /api/*  <- SQLite (WAL)  <- engine heartbeat"),
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
                  "once and recorded. The current version adds attribution_method, trigger_rule, source and the "
                  "report columns on top of the prototype shape; the migration flag prevents a second import of "
                  "the same legacy file."),
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
            ("p", "The suite contains 57 tests across seven modules, plus a negative-control script and recorded "
                  "end-to-end runs. The tests avoid the filesystem where possible and exercise the rules, the "
                  "database, the Sysmon XML parser, the threat-intel cache, the PDF writer, the HTTP API and the "
                  "simulator guardrails."),
            ("table", ["Module", "Tests", "Coverage"], TEST_ROWS, [26, 8, 66]),
            ("h2", "11.1 Recorded evidence"),
            ("bullets", [
                "pytest: 57 passed.",
                "Negative control: three creates, one append, one rename and one delete produced zero alerts.",
                "Live Sysmon run: three Critical canary findings and one High mass-change finding, all attributed "
                "to python.exe with attribution_method='sysmon' (8/8 attributed across two runs, two distinct PIDs).",
                "Docker: image built, compose stack healthy, 65/65 API and runtime checks, findings survived a restart.",
                "End-to-end lab run: 3 Critical + 1 High findings, four PDF reports, heartbeat present, no tracebacks.",
            ]),
            ("h2", "11.2 Negative control"),
            ("p", "A detector that alerts on everything would pass an attack test, so the suite includes the "
                  "opposite check: six ordinary operations in the lab, then an assertion that the findings table "
                  "is still empty."),
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
                  "store, replaced guessing with Sysmon correlation and an honest fallback, and made the whole "
                  "system reproducible on another machine through Docker and a 57-test suite."),
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
                "Python 3.12+ is required; runtime dependencies are watchdog, psutil and fpdf2.",
            ]),
            ("h1", "7. Acceptance"),
            ("p", "The system is accepted when the full test suite passes, the negative control produces no "
                  "findings, a simulated attack produces canary and mass-change findings with PDF reports, a live "
                  "Sysmon run attributes those findings to the writing process, and the compose stack starts "
                  "healthy and serves the same evidence over HTTP."),
        ],
    )


def architecture() -> Document:
    return Document(
        key="architecture",
        filename="03_System_Architecture.pdf",
        title="System Architecture",
        subtitle="Components, data flow, concurrency model and deployment topologies.",
        blocks=[
            ("h1", "1. Overview"),
            ("p", "Repo-Canary is a set of cooperating processes around one SQLite database. The engine owns "
                  "writes; the dashboard server owns reads; the simulator stands in for an attacker during drills. "
                  "Nothing is shared through memory, which is what allows a native Windows run and a two-container "
                  "deployment to use the same code."),
            ("h1", "2. Components"),
            ("table", ["Component", "File", "Responsibility"], [
                ["Engine", "scripts/detection_engine.py", "Observer, rules, persistence, enrichment queue, counters, heartbeat, shutdown."],
                ["Rules", "scripts/detection_rules.py", "Canary and mass-change decisions, event counting."],
                ["Database", "scripts/database.py", "Schema, WAL connections, dedupe insert, queries, migration, heartbeat."],
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
                     "Dashboard --> SELECT ... --> JSON --> index.html"),
            ("h1", "4. Concurrency"),
            ("bullets", [
                "The watchdog callback never performs I/O beyond the finding insert.",
                "One enrichment thread serialises Sysmon queries and hashing; the queue is bounded at 1000 jobs and drops loudly.",
                "One reporter thread serialises PDF rendering behind a throttle.",
                "Counters are buffered in memory and flushed every two seconds to minimise write amplification.",
                "Each database operation opens its own connection with WAL and a busy timeout, so the dashboard never blocks the engine.",
                "SIGINT and SIGTERM set a stop event; the observer, workers and heartbeat drain before exit.",
            ]),
            ("h1", "5. Failure handling"),
            ("table", ["Failure", "Behaviour"], [
                ["Observer thread dies", "The main loop notices and exits 1 so a supervisor restarts the service."],
                ["Sysmon missing or unreadable", "Attribution probes one record; findings store 'none' with a warning."],
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
        ],
    )


def database_doc() -> Document:
    return Document(
        key="database",
        filename="04_Database_Design.pdf",
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
            ("h1", "4. Integrity rules"),
            ("bullets", [
                "severity is constrained to the six allowed values; severity_rank stores the numeric order.",
                "rule is one of hash_match, canary, mass_change or legacy; trigger_rule records which rule fired first.",
                "attribution_method is sysmon, heuristic or none - the column cannot claim an unnamed source.",
                "dedupe_key is UNIQUE, so a restart or a repeated alert cannot duplicate evidence.",
                "processes rows are de-duplicated by (name, exe_path, cmdline) and reused by foreign key.",
                "known_hashes enforces a 64-character SHA-256.",
            ]),
            ("h1", "5. Indexes"),
            ("table", ["Index", "Columns", "Used for"], INDEX_ROWS, [22, 32, 46]),
            ("h1", "6. Write path"),
            ("p", "The engine builds an in-memory finding record, derives a dedupe key from the rule, the path and "
                  "a time bucket, and inserts with ON CONFLICT(dedupe_key) DO NOTHING. INSERT OR REPLACE is "
                  "deliberately not used: it deletes and re-inserts the row, which resets the primary key and "
                  "discards enrichment already attached to the evidence."),
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
                     "  GROUP BY p.name ORDER BY hits DESC;"),
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
        filename="06_Testing_Report.pdf",
        title="Testing Report",
        subtitle="57 automated tests, negative control, live Sysmon verification and Docker run.",
        blocks=[
            ("h1", "1. Strategy"),
            ("p", "Testing is layered. Unit tests exercise the rules, the schema and the parsers without a real "
                  "filesystem. Integration tests start the real engine against a disposable folder. End-to-end "
                  "tests run a full simulated attack and inspect the resulting rows and PDFs. Interface tests call "
                  "the HTTP API. Manual capture in the lab VM records Sysmon evidence. Every claim in this report "
                  "comes from a command whose output was inspected."),
            ("h1", "2. Environment"),
            ("table", ["Item", "Value"], [
                ["Operating system", "Windows 11, Python 3.13 virtual environment (image uses 3.12)"],
                ["Runtime dependencies", "watchdog 6.0.0, psutil 7.2.2, fpdf2 2.9.0"],
                ["Sysmon", "15.22, config Sysmon/sysmonconfig.xml"],
                ["Container", "Docker 28.5.2, Compose 2.40.3, buildx 0.29.1"],
                ["Dashboard", "127.0.0.1:8000, SQLite evidence store"],
            ], [30, 70]),
            ("h1", "3. Automated tests"),
            ("p", "pytest collects 57 tests. The table lists what each module protects."),
            ("table", ["Module", "Tests", "Coverage"], TEST_ROWS, [26, 8, 66]),
            ("h1", "4. Negative control"),
            ("p", "scripts/negative_control_test.py performs three creates, one append, one rename and one delete "
                  "in the lab and asserts that no finding was written. It exists because a detector that alerts on "
                  "everything would otherwise look successful."),
            ("code", "$ python scripts/negative_control_test.py\n"
                     "Activity:   3 creates, 1 append, 1 rename, 1 delete\n"
                     "Expectation: no alert\nAlerts:     0\n"
                     "[PASS] Normal activity produced no alert (no false positive)."),
            ("h1", "5. End-to-end drill"),
            ("p", "The simulator reverses and renames every .txt file in the marked lab. The engine produced three "
                  "Critical canary findings and one High mass-change finding, wrote four PDF incident reports, "
                  "kept the heartbeat current and left no tracebacks in the log."),
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
            ("h1", "7. Interface tests"),
            ("p", "The API suite runs the real server against a temporary database and checks every route, the "
                  "filters, pagination boundaries, both export formats, the legacy alias, and that source files "
                  "return 404. The browser page is checked for the vendored chart bundle and the API paths it uses."),
            ("h1", "8. Packaging verification"),
            ("p", "The Docker image built in 22 steps and produced a 188 MB image. The compose stack started with a "
                  "healthy dashboard; 65 runtime and API checks passed inside the containers, findings survived a "
                  "restart, and the CSV/JSONL exports matched the reported total."),
            ("h1", "9. Remaining gaps"),
            ("bullets", [
                "No long-duration false-positive measurement beyond the negative control.",
                "No load test of the enrichment queue under a sustained multi-thousand-file burst.",
                "Attribution verified on one host with one Sysmon version.",
                "A Windows bind mount instead of the named volume was not exercised for inotify propagation.",
            ]),
        ],
    )


def manual() -> Document:
    return Document(
        key="manual",
        filename="07_User_Manual.pdf",
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
            ("h1", "2. Start the engine"),
            ("code", "python scripts\\reset_lab.py --yes\n"
                     "python scripts\\detection_engine.py\n\n"
                     "Watching:    C:\\RansomwareLab\\testdata\n"
                     "Database:    C:\\RansomwareLab\\canary.db\n"
                     "Attribution: sysmon\nStatus: WATCHING"),
            ("p", "The banner states the watched folder, the database, the report folder, the number of hashes "
                  "loaded and the attribution method. If it says 'none' while you expected 'sysmon', see the "
                  "troubleshooting section."),
            ("h1", "3. Start the dashboard"),
            ("code", "python scripts\\dashboard_server.py\n# open http://127.0.0.1:8000/"),
            ("p", "The page refreshes every two seconds. The header shows total, confirmed, critical and high "
                  "counts; a card shows the latest detection and whether the engine heartbeat is current."),
            ("h1", "4. Run a drill"),
            ("code", "python simulate_ransomware.py --dry-run   # list what would change\n"
                     "python simulate_ransomware.py             # reverse and rename in the lab"),
            ("p", "The simulator refuses to run if the folder is not a marked lab, only touches .txt files, skips "
                  "symlinks and files above 10 MB, and asks for confirmation unless --yes is given. It prints each "
                  "file it touches so you can match the output to the dashboard."),
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
            ("h1", "6. Incident reports"),
            ("p", "Each alert writes a PDF into C:\\RansomwareLab\\reports and links it from the finding. Reports "
                  "are throttled to twelve per minute and coalesced per rule and path, so a burst produces a "
                  "handful of reports rather than hundreds."),
            ("h1", "7. Reset the lab"),
            ("code", "python scripts\\reset_lab.py --yes                 # restore the disposable files\n"
                     "python scripts\\reset_lab.py --yes --clear-findings  # also empty the evidence table"),
            ("h1", "8. Troubleshooting"),
            ("table", ["Symptom", "Cause and fix"], [
                ["Banner says 'Attribution: none'", "Sysmon is not installed, or the account cannot read the channel. Install it, or run elevated / join Event Log Readers."],
                ["Dashboard is empty", "The engine has not written yet, or --db-path differs from the server's."],
                ["No alerts from the simulator", "The marker file is missing. Run reset_lab.py --yes in the watched folder."],
                ["Mass-change alerts fire during a drill", "Expected: the drill writes many files quickly; the finding is deduplicated."],
                ["CSV opens with odd characters", "Use the BOM-prefixed export the dashboard produces; it targets Excel."],
            ], [32, 68]),
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
            ("h1", "6. Verification"),
            ("code", "python -m pytest -q                     # expect 57 passed\n"
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
                "Honest attribution: Sysmon correlation when available, 'none' when it is not.",
                "Asynchronous enrichment and PDF reporting, so the watchdog thread never blocks.",
                "Paginated JSON API with CSV and JSONL export, feeding a Chart.js dashboard.",
                "Multi-stage Docker image, non-root user, shared volume, healthcheck.",
                "57 automated tests, a negative control and recorded end-to-end evidence.",
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
                ["scripts/attribution.py", "Sysmon Event ID 11 correlation and psutil enrichment."],
                ["scripts/threat_intel.py", "Local SHA-256 feed with cache and reload."],
                ["scripts/reporting.py", "PDF incident reports and throttle."],
                ["scripts/dashboard_server.py", "Read-only HTTP API and static dashboard."],
                ["index.html", "Dashboard UI (vendored Chart.js)."],
                ["simulate_ransomware.py", "Harmless drill inside a marked lab."],
                ["Sysmon/sysmonconfig.xml", "Sysmon configuration for the lab folders."],
                ["tests/", "57 tests across seven modules."],
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
                  "read access to its channel."),
        ],
    )


def future() -> Document:
    return Document(
        key="future",
        filename="10_Future_Scope.pdf",
        title="Future Scope",
        subtitle="Directions that build on the current evidence pipeline.",
        blocks=[
            ("h1", "1. Alert delivery"),
            ("p", "Findings currently surface in the dashboard and on disk. Email or webhook delivery for Critical "
                  "and Confirmed Ransomware severities would make the system useful on an unattended host, with "
                  "the reporter's throttle reused to avoid notification storms."),
            ("h1", "2. Decision-model triage"),
            ("p", "Enrichment is the natural place for a triage stage: severity, process reputation, path entropy "
                  "and hash intelligence are already on the row. A decision model could recommend escalation "
                  "without changing the detection path. This was explicitly out of scope in the current pass."),
            ("h1", "3. Authentication and transport security"),
            ("p", "The dashboard is loopback-only and unauthenticated. A token or session login plus TLS would let "
                  "it serve an analyst workstation on the network without exposing evidence to anyone who can "
                  "reach the port."),
            ("h1", "4. Retention and volume growth"),
            ("p", "Evidence is append-only. A retention policy (age-based, or keep every Critical and prune "
                  "routine mass-change rows) and a scheduled database checkpoint would keep canary.db small on a "
                  "long-running server."),
            ("h1", "5. Behavioural detection"),
            ("p", "The current rules are deliberately simple and explainable. Adding entropy sampling or "
                  "content-change ratios would catch a file that is modified and later renamed, which the canary "
                  "and rate rules see only as unrelated events."),
            ("h1", "6. Multi-host aggregation"),
            ("p", "Each host writes its own database. Shipping findings to a central collector would allow one "
                  "dashboard across a fleet; the JSON API and the stable schema make the export straightforward, "
                  "and the dedupe key already prevents duplicates on the collector side."),
            ("h1", "7. Operational packaging"),
            ("bullets", [
                "A Windows service wrapper so the engine starts before a user logs in.",
                "Signed Sysmon and engine configuration, verified at startup.",
                "Structured JSON logging alongside the rotating text log.",
                "A health endpoint that reports queue depth and last enrichment latency.",
            ]),
            ("h1", "8. Response actions"),
            ("p", "Containment - suspending a process, quarantining a folder, snapshotting before encryption "
                  "spreads - is the obvious next capability. It needs carefully scoped guardrails, because a "
                  "detector that can also act on a false positive can cause the damage it is meant to prevent."),
        ],
    )


def synopsis() -> Document:
    return Document(
        key="synopsis",
        filename="12_Synopsis.pdf",
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
                ["Evidence", "SQLite (WAL)", "findings, processes, hashes, counters, heartbeat."],
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
                  "database through WAL, so it never blocks the writer."),
            ("p", "Attribution was verified against a live Sysmon 15.22 installation: every canary and mass-change "
                  "finding in the drill was attributed to the simulator process, with the correct PID and user, "
                  "across two runs and two distinct PIDs."),
            ("h1", "7. Results"),
            ("table", ["Check", "Result"], [
                ["Automated suite", "57 tests passed."],
                ["Negative control", "PASS - three creates, one append, one rename, one delete produced zero alerts."],
                ["End-to-end drill", "3 Critical canary + 1 High mass-change findings, 4 PDF reports, no tracebacks."],
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
            ]),
            ("h1", "9. Future work"),
            ("p", "Alert delivery, decision-model triage on the enriched row, authentication and TLS, retention "
                  "policies, entropy-based detection and multi-host aggregation are the natural next steps. "
                  "Containment actions would follow once false-positive behaviour is characterised over a longer "
                  "period."),
            ("h1", "10. Conclusion"),
            ("p", "The project delivers a defensible detection pipeline: explainable rules, a durable evidence "
                  "store, real process attribution with an honest fallback, incident reports and a dashboard, all "
                  "reproducible on another machine and backed by an automated suite."),
            ("h1", "11. References"),
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
          "Enrichment worker: Sysmon Event ID 11, SHA-256, PDF report.",
          "Dashboard server reads the same database through WAL.",
          "Simulator plays the attacker inside a marked lab."]),
        ("Detection Rules",
         ["Canary: any touch of three disposable files -> Critical.",
          "Mass change: 10 events in 10 s -> High, debounced at 0.5 s.",
          "Hash match against the local feed -> Confirmed Ransomware.",
          "Renames counted once, destination still canary-checked."]),
        ("Evidence Store: SQLite",
         ["Tables: findings, processes, known_hashes, event_counters, engine_state.",
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
         ["57 automated tests across seven modules.",
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
          "Reproducible on another machine; 57 tests backing every claim."]),
    ]

    return Document(
        key="deck",
        filename="11_Project_Presentation.pdf",
        title="Project Presentation",
        subtitle="Slide deck.",
        landscape=True,
        blocks=[("slide", title, bullets) for title, bullets in slides],
    )


DOCUMENTS = [
    report(),
    srs(),
    architecture(),
    database_doc(),
    api_doc(),
    testing_doc(),
    manual(),
    installation(),
    readme(),
    future(),
    deck(),
    synopsis(),
]

MARKDOWN_FILES = {
    "readme": "README.md",
    "install": "INSTALLATION_GUIDE.md",
    "database": "DATABASE_SCHEMA.md",
    "api": "API_DOCUMENTATION.md",
}
