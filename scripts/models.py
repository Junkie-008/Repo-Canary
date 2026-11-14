"""Shared domain models for the detection engine, database and dashboard.

Keeping these in one module means the engine, the persistence layer and the
HTTP API agree on severity ordering, process details and finding shape.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Optional

# Highest first. The numeric rank is stored so queries never need a CASE.
SEVERITY_RANK = {
    "Confirmed Ransomware": 5,
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}

SEVERITY_ORDER = tuple(SEVERITY_RANK)

RULES = ("hash_match", "canary", "mass_change", "legacy")


def severity_rank(severity: str) -> int:
    """Return the numeric rank for a severity, defaulting to Info."""

    return SEVERITY_RANK.get(severity, 0)


def normalize_severity(severity: Optional[str]) -> str:
    """Map an unknown severity string onto the Info bucket."""

    return severity if severity in SEVERITY_RANK else "Info"


@dataclass(frozen=True)
class ProcessDetails:
    """Snapshot of the process attributed to a file event."""

    pid: int
    name: str
    exe_path: Optional[str] = None
    cmdline: tuple[str, ...] = ()
    username: Optional[str] = None


@dataclass(frozen=True)
class IntelResult:
    """Outcome of hashing a file and checking it against the local feed."""

    sha256: Optional[str] = None
    label: Optional[str] = None
    error: Optional[str] = None

    @property
    def matched(self) -> bool:
        return self.label is not None


def make_dedupe_key(
    rule: str,
    path: Optional[str],
    event_type: Optional[str],
    occurred_at: str,
    bucket_seconds: int = 1,
) -> str:
    """Build an idempotency key for one logical event.

    The timestamp is truncated to a whole second: the engine's debounce window
    is 0.5 s, so two events inside this bucket are the same operation. The key
    survives process restarts, which is what makes re-delivery safe.
    """

    bucket = occurred_at[:19] if len(occurred_at) >= 19 else occurred_at
    normalized_path = os.path.normcase(os.path.normpath(str(path))) if path else ""
    raw = f"{rule}|{normalized_path}|{event_type or ''}|{bucket}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


@dataclass
class FindingRecord:
    """One row destined for the findings table."""

    occurred_at: str
    summary: str
    severity: str
    rule: str
    trigger_rule: Optional[str] = None
    path: Optional[str] = None
    event_type: Optional[str] = None
    process: Optional[ProcessDetails] = None
    attribution_method: str = "none"
    file_sha256: Optional[str] = None
    intel_label: Optional[str] = None
    matched_hash: Optional[str] = None
    source: str = "engine"
    dedupe_key: str = field(default="")

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)

        if not self.dedupe_key:
            self.dedupe_key = make_dedupe_key(
                self.rule,
                self.path,
                self.event_type,
                self.occurred_at,
            )
