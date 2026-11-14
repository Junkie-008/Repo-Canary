"""Persisted canary baseline and integrity scans.

watchdog events are the primary signal, but they only exist while the engine is
running. A canary renamed during a restart, or an event the observer never
delivered, would otherwise leave no trace. Each canary therefore has a stored
baseline (SHA-256, size, mtime) in SQLite; the engine verifies it at startup
and periodically and raises the same Critical canary finding when a file is
missing, modified, touched or replaced.

The baseline is written by ``reset_lab.py`` when the lab is created, and is
seeded from the canonical canary content for databases created before this
feature. Hashing is capped so a hostile replacement cannot make the scan read
an unbounded file.
"""

from __future__ import annotations

import hashlib
import logging
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional

import lab_config
from database import utc_now
from detection_rules import CANARY_FILES

logger = logging.getLogger("repo_canary.integrity")

# A canary is a one-line text file. Anything larger is not a canary any more.
MAX_CANARY_BYTES = 1024 * 1024

_CANONICAL_BYTES = lab_config.CANARY_TEXT.encode("utf-8")
# Labs created before reset_lab wrote bytes were CRLF on Windows. Accept that
# exact form when seeding an old database, but never arbitrary content.
_CANONICAL_CRLF_BYTES = lab_config.CANARY_TEXT.replace("\n", "\r\n").encode("utf-8")
CANONICAL_SHA256 = hashlib.sha256(_CANONICAL_BYTES).hexdigest()
CANONICAL_SIZE = len(_CANONICAL_BYTES)


@dataclass(frozen=True)
class CanaryState:
    """Result of inspecting one canary against its baseline."""

    name: str
    path: Path
    kind: Optional[str] = None  # None means the canary matches its baseline
    observed_sha256: Optional[str] = None
    observed_size: Optional[int] = None
    baseline_sha256: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.kind is None


@dataclass(frozen=True)
class CanaryProblem:
    """A state change that must become a Critical canary finding."""

    name: str
    path: str
    kind: str
    summary: str
    event_type: str
    baseline_sha256: Optional[str] = None
    observed_sha256: Optional[str] = None


def _baseline_entry(name: str, data: bytes, mtime_ns: Optional[int]) -> dict:
    return {
        "name": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "mtime_ns": mtime_ns,
        "captured_at": utc_now(),
    }


def lab_baseline_entries(test_dir: Path | str) -> list[dict]:
    """Capture the canaries that ``reset_lab`` has just written."""

    directory = Path(test_dir)
    entries = []

    for name in sorted(CANARY_FILES):
        path = directory / name
        entries.append(
            _baseline_entry(name, path.read_bytes(), path.stat().st_mtime_ns)
        )

    return entries


def canonical_baseline_entries() -> list[dict]:
    """Baseline derived from the canonical content, with no timestamp.

    Used when an existing database predates the baseline table: the known
    content is a safer starting point than trusting whatever is on disk now.
    """

    captured_at = utc_now()

    return [
        {
            "name": name,
            "sha256": CANONICAL_SHA256,
            "size": CANONICAL_SIZE,
            "mtime_ns": None,
            "captured_at": captured_at,
        }
        for name in sorted(CANARY_FILES)
    ]


def seed_entries_for(test_dir: Path | str, names: list[str]) -> list[dict]:
    """Seed missing baseline rows without blessing tampered canaries.

    A file whose bytes are exactly the canonical LF or legacy CRLF form is
    recorded as it is on disk, so an upgrade does not raise false alarms. Any
    other content (or a missing file) gets the canonical LF hash, which makes
    the first scan report it as modified or missing.
    """

    directory = Path(test_dir)
    captured_at = utc_now()
    allowed = {_CANONICAL_BYTES, _CANONICAL_CRLF_BYTES}
    entries = []

    for name in sorted(names):
        path = directory / name

        try:
            data = path.read_bytes()
            mtime_ns = path.stat().st_mtime_ns
        except OSError:
            data, mtime_ns = None, None

        if data in allowed and len(data) <= MAX_CANARY_BYTES:
            entries.append(_baseline_entry(name, data, mtime_ns))
        else:
            entries.append(
                {
                    "name": name,
                    "sha256": CANONICAL_SHA256,
                    "size": CANONICAL_SIZE,
                    "mtime_ns": None,
                    "captured_at": captured_at,
                }
            )

    return entries


def _hash_capped(path: Path) -> tuple[Optional[str], Optional[int], Optional[str]]:
    """Return ``(sha256, size, error_kind)`` without reading past the cap."""

    digest = hashlib.sha256()
    total = 0

    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                total += len(chunk)

                if total > MAX_CANARY_BYTES:
                    return None, total, "oversized"

                digest.update(chunk)
    except OSError:
        return None, total, "unreadable"

    return digest.hexdigest(), total, None


def scan_canaries(
    test_dir: Path | str,
    baseline: Mapping[str, Mapping],
) -> list[CanaryState]:
    """Inspect every canary once. No filesystem state is changed."""

    directory = Path(test_dir)
    states = []

    for name in sorted(CANARY_FILES):
        path = directory / name
        row = baseline.get(name) or {}
        baseline_sha = row.get("sha256")

        try:
            info = path.lstat()
        except FileNotFoundError:
            states.append(CanaryState(name, path, "missing", baseline_sha256=baseline_sha))
            continue
        except OSError:
            states.append(CanaryState(name, path, "unreadable", baseline_sha256=baseline_sha))
            continue

        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            states.append(
                CanaryState(
                    name,
                    path,
                    "replaced",
                    observed_size=info.st_size,
                    baseline_sha256=baseline_sha,
                )
            )
            continue

        digest, size, error = _hash_capped(path)

        if error:
            kind = error
        elif not row:
            kind = "unbaselined"
        elif digest != baseline_sha:
            kind = "modified"
        elif row.get("mtime_ns") is not None and info.st_mtime_ns != row["mtime_ns"]:
            kind = "touched"
        else:
            kind = None

        states.append(
            CanaryState(
                name,
                path,
                kind,
                observed_sha256=digest,
                observed_size=size,
                baseline_sha256=baseline_sha,
            )
        )

    return states


_PROBLEM_TEXT = {
    "missing": "Canary file missing during {label}",
    "modified": "Canary file modified during {label}",
    "touched": "Canary file timestamp changed during {label}",
    "replaced": "Canary file replaced by a non-regular file during {label}",
    "oversized": "Canary file exceeds the integrity scan size limit during {label}",
    "unreadable": "Canary file unreadable during {label}",
    "unbaselined": "Canary file has no baseline entry during {label}",
}


def problem_for(state: CanaryState, event_type: str) -> CanaryProblem:
    """Turn a non-OK state into a finding payload."""

    label = (
        "the startup integrity scan"
        if event_type == "startup_scan"
        else "a periodic integrity scan"
    )
    text = _PROBLEM_TEXT.get(state.kind or "", "Canary file failed its integrity check")

    return CanaryProblem(
        name=state.name,
        path=str(state.path),
        kind=state.kind or "unknown",
        summary=f"{text.format(label=label)}: {state.path}",
        event_type=event_type,
        baseline_sha256=state.baseline_sha256,
        observed_sha256=state.observed_sha256,
    )


class CanaryIntegrityMonitor:
    """Scan the baseline at startup and on an interval, alerting on change.

    A live watchdog alert marks the canary as already reported, so the next
    periodic scan does not raise a duplicate. A state change (for example a
    modified canary that is then deleted) still produces a new finding.
    """

    def __init__(
        self,
        test_dir: Path | str,
        baseline_loader: Callable[[], Mapping[str, Mapping]],
        on_problem: Callable[[CanaryProblem], None],
        interval: float = 300.0,
    ):
        self.test_dir = Path(test_dir)
        self.baseline_loader = baseline_loader
        self.on_problem = on_problem
        self.interval = max(0.0, float(interval))
        self._states: dict[str, str] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def scan(self, *, event_type: str = "integrity_scan", force: bool = False) -> list[CanaryProblem]:
        baseline = self.baseline_loader()
        states = scan_canaries(self.test_dir, baseline)
        problems = []

        with self._lock:
            for state in states:
                kind = state.kind or "ok"
                previous = self._states.get(state.name)
                self._states[state.name] = kind

                if state.ok:
                    if previous not in (None, "ok"):
                        logger.warning("Canary %s is back at its baseline", state.name)
                    continue

                # "live" means the watchdog already raised this canary; suppress
                # the duplicate scan finding, but keep the new state so an
                # escalation (modified -> missing) is reported.
                if force or (previous != kind and previous != "live"):
                    problems.append(problem_for(state, event_type))

        for problem in problems:
            try:
                self.on_problem(problem)
            except Exception:  # noqa: BLE001 - one bad callback must not stop the scan
                logger.exception("Could not persist canary integrity problem %s", problem.name)

        return problems

    def note_live_alert(self, path: str | Path) -> None:
        """Remember that watchdog already reported this canary."""

        name = Path(path).name

        if name not in CANARY_FILES:
            return

        with self._lock:
            self._states[name] = "live"

    def start(self) -> None:
        if self.interval <= 0 or self._thread is not None:
            return

        self._thread = threading.Thread(
            target=self._run,
            name="canary-integrity",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.scan()
            except Exception:  # noqa: BLE001 - a scan failure must not kill the thread
                logger.exception("Periodic canary integrity scan failed")
