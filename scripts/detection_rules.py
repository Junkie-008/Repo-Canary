"""Pure detection rules for Ransomware 207.

This module deliberately imports nothing from watchdog or psutil so the
rules can be unit-tested without a Windows lab folder or real file events.

Rules
-----
Canary      A canary file is modified/moved -> Critical alert.
Mass change 10 normalised events within 10 seconds -> High alert,
            repeated at most once every 10 seconds while the burst lasts.
Debounce    Repeated events for the same path within 0.5 seconds are
            collapsed into one event before any rule is evaluated. This is
            what keeps a single canary operation from producing two or
            three duplicate Critical findings.

Callers pass the current time in (`now`) when they need deterministic
behaviour; otherwise time.time() is used.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

CANARY_FILES = frozenset({
    "_canary_01.txt",
    "_canary_02.txt",
    "_canary_03.txt",
})

RATE_WINDOW_SECONDS = 10
RATE_THRESHOLD = 10

# Ignore repeated events for the same file inside this period.
DEBOUNCE_SECONDS = 0.5

# Prevent repeated mass-change alerts during the same burst.
ALERT_COOLDOWN_SECONDS = 10


@dataclass(frozen=True)
class Alert:
    """A finding produced by a rule, ready to print and persist."""

    time: str
    severity: str
    summary: str
    event_type: str
    path: str


@dataclass(frozen=True)
class EventResult:
    """Outcome of one filesystem event.

    `accepted` is False when the event was debounced, so callers can skip
    logging it. `event_count` is the number of events currently inside the
    rolling window.
    """

    accepted: bool
    event_count: int
    alerts: tuple[Alert, ...]


def _format_time(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


class DetectionRules:
    """Stateful canary + mass-change detector over filesystem events."""

    def __init__(
        self,
        canary_files: Iterable[str] = CANARY_FILES,
        rate_window_seconds: float = RATE_WINDOW_SECONDS,
        rate_threshold: int = RATE_THRESHOLD,
        debounce_seconds: float = DEBOUNCE_SECONDS,
        alert_cooldown_seconds: float = ALERT_COOLDOWN_SECONDS,
        clock=time.time,
    ):
        self.canary_files = frozenset(name.lower() for name in canary_files)
        self.rate_window_seconds = rate_window_seconds
        self.rate_threshold = rate_threshold
        self.debounce_seconds = debounce_seconds
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self.clock = clock

        # Timestamps of normalised (post-debounce) file events.
        self.event_times = deque()

        # Most recent accepted event for each path.
        self.last_file_event = {}

        # Timestamp of the last mass-change alert.
        self.last_rate_alert: Optional[float] = None

    # ------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------

    def is_canary(self, path) -> bool:
        return Path(path).name.lower() in self.canary_files

    @property
    def event_count(self) -> int:
        return len(self.event_times)

    def _prune(self, now: float) -> None:
        while (
            self.event_times
            and now - self.event_times[0] > self.rate_window_seconds
        ):
            self.event_times.popleft()

    # ------------------------------------------------------------
    # Event processing
    # ------------------------------------------------------------

    def process_event(
        self,
        event_type: str,
        path,
        now: Optional[float] = None,
        is_directory: Optional[bool] = None,
    ) -> EventResult:
        """Evaluate one filesystem event and return the alerts it raises.

        Directory events are ignored at this level. Pass `is_directory`
        explicitly when the caller already knows (watchdog does); otherwise
        the path is checked on disk.
        """

        if now is None:
            now = self.clock()

        path = str(path)

        if is_directory is None:
            is_directory = Path(path).is_dir()

        if is_directory:
            return EventResult(accepted=False, event_count=self.event_count, alerts=())

        # Debounce first, so one file operation counts once and alerts once.
        previous_event = self.last_file_event.get(path)

        if (
            previous_event is not None
            and now - previous_event < self.debounce_seconds
        ):
            return EventResult(accepted=False, event_count=self.event_count, alerts=())

        self.last_file_event[path] = now
        self.event_times.append(now)
        self._prune(now)

        alerts = []

        # ----------------------------------------------------
        # Canary rule
        # ----------------------------------------------------

        if self.is_canary(path):
            alerts.append(
                Alert(
                    time=_format_time(now),
                    severity="Critical",
                    summary=f"Canary file detected: {path}",
                    event_type=event_type,
                    path=path,
                )
            )

        # ----------------------------------------------------
        # Mass-change rule
        # ----------------------------------------------------

        cooldown_passed = (
            self.last_rate_alert is None
            or now - self.last_rate_alert >= self.alert_cooldown_seconds
        )

        if self.event_count >= self.rate_threshold and cooldown_passed:
            alerts.append(
                Alert(
                    time=_format_time(now),
                    severity="High",
                    summary=(
                        f"Mass-change detected: {self.event_count} events "
                        f"in {self.rate_window_seconds} seconds"
                    ),
                    event_type=event_type,
                    path=path,
                )
            )

            self.last_rate_alert = now

        return EventResult(
            accepted=True,
            event_count=self.event_count,
            alerts=tuple(alerts),
        )
