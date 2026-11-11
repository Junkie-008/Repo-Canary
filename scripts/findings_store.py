"""Persistence for Ransomware 207 findings.

findings.json is a JSON list of {time, summary, severity} objects, capped
at the most recent 50 entries (FR-3.1).

Writes are atomic: the new list is written to a temporary file in the same
folder and then moved over findings.json with os.replace(). The dashboard
polls the file every 3 seconds, so it must never read a half-written file.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

MAX_FINDINGS = 50
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def load_findings(findings_file) -> list:
    """Return the findings list, or [] if the file is missing or invalid."""

    findings_file = Path(findings_file)

    if not findings_file.exists():
        return []

    try:
        with findings_file.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return []

    return data if isinstance(data, list) else []


def save_finding(
    summary: str,
    severity: str = "Info",
    findings_file=None,
    timestamp: Optional[str] = None,
) -> dict:
    """Append one finding and atomically rewrite findings.json.

    Returns the entry that was written.
    """

    if findings_file is None:
        import lab_config

        findings_file = lab_config.FINDINGS_FILE

    findings_file = Path(findings_file)
    findings_file.parent.mkdir(parents=True, exist_ok=True)

    data = load_findings(findings_file)

    entry = {
        "time": timestamp or datetime.now().strftime(TIME_FORMAT),
        "summary": summary,
        "severity": severity,
    }

    data.append(entry)
    data = data[-MAX_FINDINGS:]

    # Write next to the target so os.replace() stays on the same volume.
    descriptor, temp_path = tempfile.mkstemp(
        dir=str(findings_file.parent),
        prefix=".findings-",
        suffix=".tmp",
    )

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, findings_file)

    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass

        raise

    return entry
