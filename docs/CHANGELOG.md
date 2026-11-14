# Changelog

All notable changes to Ransomware 207 (Repo-Canary) and its documentation.

## [3.0] - 2026-11-14

### Documentation

- Rebuilt every PDF in this folder from `docs_content.py` with one consistent
  template (`docs_builder.py`, fpdf2). The set is now reproducible:
  `python build_docs.py` regenerates all twelve PDFs.
- Content brought in line with the current implementation: SQLite evidence
  store, Sysmon Event ID 11 attribution (with the honest `none` fallback and
  the three defects fixed during the live run), 57 automated tests, PDF
  incident reports, paginated API and Docker packaging.
- Presentation rebuilt as a 16:9 PDF and an edited `.pptx` from the same slide
  content.
- `README.md`, `INSTALLATION_GUIDE.md`, `DATABASE_SCHEMA.md` and
  `API_DOCUMENTATION.md` are now generated from the same blocks as the PDFs,
  so they cannot drift from them.
- Added contents pages with verified page numbers, requirement tables and a
  requirements-traceability matrix.

## [2.0] - 2026-11-11

### Documentation

- Replaced the separate SRS, Synopsis, Use-Case and Day 4 support documents with
  one consolidated 35-page project report covering 17 sections.
- Added the numbered companion set: `02_SRS_Document`, `03_System_Architecture`,
  `04_Database_Design`, `05_API_Documentation`, `06_Testing_Report`,
  `08_Installation_Guide`, `09_README` and `10_Future_Scope`, generated from the
  report and the Markdown sources so the two never disagree.
- Added a 17-slide project presentation (PPTX and PDF) reflecting the current
  results and user interface, including an evidence slide.
- Added a 10-page user manual (DOCX and PDF).
- Added `12_Synopsis.docx` / `.pdf`: a 15-page synopsis with the abstract, objectives,
  methodology, implementation, results, limitations, future scope and references.
- Added `README.md`, `API_DOCUMENTATION.md`, `DATABASE_SCHEMA.md`,
  `INSTALLATION_GUIDE.md` and this changelog.
- Moved the architecture, DFD and use-case figures into `images/` and added a
  dashboard screenshot.
- Added captured run evidence from 11-11-2026 20:45 on the development host:
  engine console (Figure 12.1), unit tests (12.2), negative control (12.3) and a
  refreshed dashboard capture (Figure 10.1). Sysmon Event ID 11 remains a
  separate capture in the lab VM.

### Changed

- Documentation now reports the validated negative-control result (0 alerts on
  11-11-2026) instead of listing it as pending.
- Documentation describes the duplicate-canary fix, atomic persistence, the 19
  automated tests and the new dashboard controls.

## [1.1] - 2026-11-11

### Fixed

- **Duplicate canary findings:** the debounce now runs before the canary rule,
  so one file operation produces one finding.
- **Detector crash on redirected output:** stdout/stderr are reconfigured to
  UTF-8 with replacement, so an emoji alert cannot stop the watchdog thread.
- **Partial findings file reads:** `findings.json` is written to a temporary
  file and moved into place atomically with `os.replace`.
- **Hard-coded lab paths:** paths are now supplied by `scripts/lab_config.py`
  and can be overridden with CLI flags or `REPO_CANARY_*` environment variables.

### Added

- `scripts/detection_rules.py`: pure canary, rate, debounce and cooldown rules.
- `scripts/findings_store.py`: atomic, capped JSON persistence.
- `scripts/negative_control_test.py`: automated FR-1.4 evidence.
- `scripts/reset_lab.py`: restores canaries and disposable files.
- `scripts/dashboard_server.py`: serves the dashboard and `/findings.json`.
- `tests/`: 19 pytest tests for the rules and persistence.
- `pytest.ini`, `requirements.txt` and `requirements-dev.txt`.
- Sysmon FileCreate rule for `C:\RansomwareLab\testdata\`.
- Dashboard search, severity filters, pause/resume, manual refresh, CSV export
  and resilient error handling.
- Expanded `README.md` and `EVIDENCE_CHECKLIST.md`.

### Verified

- 19 unit tests pass.
- Negative control: 0 alerts on ordinary activity.
- End-to-end run: 3 Critical canary findings (one per file) and 1 High
  mass-change finding, with no duplicates.
- Dashboard: HTTP 200 for `/findings.json`, 4 of 4 rows rendered in a browser.
- Sysmon configuration: valid XML with two FileCreate rules.

### Repository

- Untracked generated `findings.json` and `testdata/*.locked` files.
- Removed the empty `detector/detector.py`.
- Commit: `5efa423` — "Make detection reliable and the demo reproducible".

## [1.0] - 2026-10-01

### Added

- Initial Day-4/Day-5 baseline: simulator, watchdog detection engine, canary and
  mass-change rules, `findings.json` persistence, static dashboard, Sysmon
  configuration and psutil process attribution.
- Initial SRS, Synopsis and Use-Case documentation.
