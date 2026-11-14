# API Documentation

*Read-only HTTP JSON API served by scripts/dashboard_server.py.*

## 1. Overview

The only network interface is a small read-only HTTP server. It serves the dashboard page, the vendored Chart.js bundle and a JSON API over the SQLite evidence store. It is bound to 127.0.0.1 by default and has no authentication or TLS; it is intended for the lab host.

```
python scripts/dashboard_server.py --host 127.0.0.1 --port 8000 \
    --db-path C:\RansomwareLab\canary.db
```

## 2. Conventions

- Responses are JSON unless a download is requested; errors are plain HTTP with a status code.
- Timestamps are UTC ISO-8601 strings; severity is the display name, severity_rank the numeric order.
- Query parameters are validated and clamped to their documented range.
- Only /, /index.html and /vendor/* are served statically; every other path returns 404.

## 3. Endpoints

| Route | Parameters | Returns |
| --- | --- | --- |
| GET / | none | Dashboard page (index.html), served with the vendored Chart.js bundle. |
| GET /vendor/<file> | none | Only the vendored assets; every other path returns 404. |
| GET /api/health | none | ok, version, database, engine heartbeat and engine_alive. |
| GET /api/findings | limit (1-500, default 50), offset, severity, rule, q, since, until | items, total, limit, offset, has_more. |
| GET /api/stats | hours (1-720, default 24) | totals, by_severity, by_rule, latest, last_finding, engine. |
| GET /api/events-per-minute | minutes (1-1440, default 60) | Per-minute event buckets. |
| GET /api/top-processes | hours (default 24), limit (1-50, default 10) | Findings grouped by process. |
| GET /api/process-heatmap | hours (1-72, default 12), top (1-20, default 8) | Hour-by-process matrix for the heatmap. |
| GET /api/export | format=csv|jsonl plus the /api/findings filters | CSV (UTF-8 BOM, quoted) or JSONL download, bounded at 10 000 rows. |
| GET /findings.json | none | Deprecated compatibility view: 50 most recent findings as time/summary/severity. |

## 4. Examples

#### Health

```
GET /api/health

{
  "ok": true,
  "version": "2.0.0",
  "database": "/data/lab/canary.db",
  "engine_alive": true,
  "engine": { "last_heartbeat": "2026-11-14T01:10:52Z",
              "heartbeat_age_seconds": 1.4, "alive": true }
}
```

#### Findings

```
GET /api/findings?severity=Critical&limit=2

{
  "items": [
    { "id": 3, "occurred_at": "2026-11-14T01:04:33Z",
      "severity": "Critical", "severity_rank": 4,
      "rule": "canary", "path": "C:\\RansomwareLab\\testdata\\_canary_03.txt",
      "pid": 12588, "attribution_method": "sysmon",
      "process": { "name": "python.exe", "username": "LAPTOP\\Abhishek" } }
  ],
  "total": 3,
  "limit": 2,
  "offset": 0,
  "has_more": true
}
```

#### Export

```
GET /api/export?format=csv&severity=Critical
Content-Type: text/csv; charset=utf-8
Content-Disposition: attachment; filename=repo-canary-findings-<stamp>.csv
```

CSV output carries a UTF-8 BOM so Excel opens it correctly, quotes every field, and neutralises leading =, +, - and @ characters to prevent formula injection. JSONL is one finding per line, encoded as UTF-8, and both formats are bounded at 10 000 rows.

## 5. Error behaviour

| Situation | Response |
| --- | --- |
| Unknown path | 404, no file contents are ever returned. |
| Unknown export format | 200 with CSV (documented fallback). |
| Database not created yet | 200 with an empty result set. |
| Engine stopped | 200 with engine_alive=false and a stale heartbeat. |

## 6. Compatibility

GET /findings.json remains as a deprecated alias for external scripts: it returns the 50 most recent findings as time, summary and severity. New integrations should use /api/findings.
