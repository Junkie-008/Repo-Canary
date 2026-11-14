"""Best-effort process attribution for file events.

``watchdog`` gives us a path, not a PID, and ``psutil`` cannot tell which
process wrote a file. The only honest source of attribution is a kernel/EDR
event that carries the PID. On Windows that is Sysmon Event ID 11.

This module correlates a file path and timestamp with recent Sysmon events,
then enriches the PID with psutil. If Sysmon is unavailable, attribution is
``None`` with method ``"none"`` — never a guess.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import psutil

from models import ProcessDetails

logger = logging.getLogger(__name__)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_QUERY = "*[System[(EventID=11)]]"
DEFAULT_WINDOW_SECONDS = 3.0
CACHE_TTL_SECONDS = 0.5
RETRY_DELAY_SECONDS = 0.4
RETRY_ATTEMPTS = 3
MAX_EVENTS = 80

_FRACTION = re.compile(r"(\.\d{6})\d+")


@dataclass(frozen=True)
class SysmonFileEvent:
    target: str
    occurred: datetime
    pid: int


def _parse_utc(value: str) -> Optional[datetime]:
    if not value:
        return None

    text = value.strip().replace(" ", "T")
    text = _FRACTION.sub(r"\1", text)

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _normalize(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def parse_sysmon_xml(xml_text: str) -> list[SysmonFileEvent]:
    """Parse Event ID 11 records from ``wevtutil ... /f:xml`` output."""

    if not xml_text.strip():
        return []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # wevtutil can emit several sibling <Event> roots; wrap them. An XML
        # declaration cannot appear inside the wrapper, so strip it first.
        cleaned = re.sub(r"^\s*<\?xml[^>]*\?>", "", xml_text)
        try:
            root = ET.fromstring(f"<Events>{cleaned}</Events>")
        except ET.ParseError as error:
            logger.warning("Could not parse Sysmon XML: %s", error)
            return []

    events: list[SysmonFileEvent] = []

    for event in root.iter():
        if not event.tag.endswith("Event"):
            continue

        data: dict[str, str] = {}
        system_utc: Optional[str] = None

        for child in event.iter():
            tag = child.tag.rsplit("}", 1)[-1]

            if tag == "TimeCreated":
                system_utc = child.attrib.get("SystemTime") or system_utc

            if tag == "Data":
                name = child.attrib.get("Name")
                if name:
                    data[name] = (child.text or "").strip()

        target = data.get("TargetFilename")
        pid_text = data.get("ProcessId")
        occurred = _parse_utc(data.get("UtcTime") or system_utc or "")

        if not target or not pid_text or occurred is None:
            continue

        try:
            pid = int(pid_text)
        except ValueError:
            continue

        events.append(SysmonFileEvent(target=target, occurred=occurred, pid=pid))

    return events


class NullAttributor:
    method = "none"

    def lookup(self, path: str, occurred: datetime) -> tuple[Optional[ProcessDetails], str]:
        return None, self.method


class SysmonAttributor:
    """Correlate file paths with recent Sysmon Event ID 11 records."""

    method = "sysmon"
    _available: Optional[bool] = None

    def __init__(
        self,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        retry_delay: float = RETRY_DELAY_SECONDS,
        retry_attempts: int = RETRY_ATTEMPTS,
    ):
        self.window_seconds = window_seconds
        self.retry_delay = retry_delay
        self.retry_attempts = max(0, retry_attempts)
        self._events: list[SysmonFileEvent] = []
        self._fetched_at = 0.0
        self._lock = threading.Lock()

    @classmethod
    def available(cls) -> bool:
        """True when the Sysmon channel is installed *and* readable by this account."""

        if cls._available is not None:
            return cls._available

        if not (sys.platform.startswith("win") and shutil.which("wevtutil")):
            cls._available = False
            return False

        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        try:
            installed = subprocess.run(
                ["wevtutil", "gl", SYSMON_CHANNEL],
                capture_output=True,
                timeout=3,
                creationflags=flags,
            )
        except (OSError, subprocess.SubprocessError):
            cls._available = False
            installed = None

        if installed is None or installed.returncode != 0:
            cls._available = False
            logger.warning(
                "Sysmon channel %s is not installed; attribution disabled",
                SYSMON_CHANNEL,
            )
            return cls._available

        # The channel can exist while the account cannot read it. Reporting
        # "sysmon" in that state would claim an attribution source the engine
        # cannot use, so probe a single record before enabling it.
        try:
            readable = subprocess.run(
                ["wevtutil", "qe", SYSMON_CHANNEL, "/c:1", "/rd:true", "/f:xml"],
                capture_output=True,
                timeout=3,
                creationflags=flags,
            )
            cls._available = readable.returncode == 0
        except (OSError, subprocess.SubprocessError):
            cls._available = False

        if not cls._available:
            logger.warning(
                "Sysmon channel %s exists but is not readable by this account; "
                "run the engine elevated or add the account to Event Log Readers",
                SYSMON_CHANNEL,
            )

        return cls._available

    def lookup(self, path: str, occurred: datetime) -> tuple[Optional[ProcessDetails], str]:
        if not self.available():
            return None, "none"

        match = self._match(path, occurred, self._recent_events())

        # watchdog can report a file before Sysmon has ghosted its Event ID 11
        # record (the lag is a few hundred milliseconds), so a live write is
        # only attributable if the channel is re-read a couple of times.
        for _ in range(self.retry_attempts):
            if match is not None:
                break

            time.sleep(self.retry_delay)
            match = self._match(path, occurred, self._recent_events(force=True))

        if match is None:
            return None, "none"

        return self._describe(match.pid), self.method

    def _match(
        self,
        path: str,
        occurred: datetime,
        events: list[SysmonFileEvent],
    ) -> Optional[SysmonFileEvent]:
        target = _normalize(path)
        candidates = [
            event
            for event in events
            if abs((event.occurred - occurred).total_seconds()) <= self.window_seconds
        ]

        match = next(
            (event for event in candidates if _normalize(event.target) == target),
            None,
        )

        if match is None:
            # Rename/delete records can use a different canonical path; fall
            # back to the same basename in the same directory.
            parent, name = os.path.split(target)
            match = next(
                (
                    event
                    for event in candidates
                    if _normalize(event.target).rsplit(os.sep, 1)[-1] == name
                    and _normalize(os.path.dirname(event.target)) == parent
                ),
                None,
            )

        return match

    def _recent_events(self, force: bool = False) -> list[SysmonFileEvent]:
        now = time.time()

        with self._lock:
            if not force and now - self._fetched_at < CACHE_TTL_SECONDS and self._events:
                return self._events

            self._fetched_at = now

            try:
                completed = subprocess.run(
                    [
                        "wevtutil",
                        "qe",
                        SYSMON_CHANNEL,
                        f"/q:{SYSMON_QUERY}",
                        "/f:xml",
                        f"/c:{MAX_EVENTS}",
                        "/rd:true",
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.SubprocessError) as error:
                logger.warning("Sysmon query failed: %s", error)
                return self._events

            if completed.returncode != 0:
                logger.warning(
                    "Sysmon query returned %s: %s",
                    completed.returncode,
                    (completed.stderr or "").strip()[:300],
                )
                return self._events

            self._events = parse_sysmon_xml(completed.stdout)
            return self._events

    @staticmethod
    def _describe(pid: int) -> ProcessDetails:
        try:
            process = psutil.Process(pid)

            try:
                exe_path = process.exe()
            except (psutil.Error, OSError):
                exe_path = None

            try:
                username = process.username()
            except (psutil.Error, OSError):
                username = None

            try:
                cmdline = tuple(process.cmdline())
            except (psutil.Error, OSError):
                cmdline = ()

            try:
                name = process.name()
            except (psutil.Error, OSError):
                name = "UNKNOWN"

            return ProcessDetails(
                pid=pid,
                name=name,
                exe_path=exe_path,
                cmdline=cmdline,
                username=username,
            )

        except (psutil.Error, OSError):
            return ProcessDetails(pid=pid, name="UNKNOWN")


def build_attributor(mode: str = "auto"):
    """Return an attributor for ``auto``, ``sysmon`` or ``none``."""

    mode = (mode or "auto").lower()

    if mode == "none":
        return NullAttributor()

    if mode in {"auto", "sysmon"} and SysmonAttributor.available():
        return SysmonAttributor()

    if mode == "sysmon":
        logger.warning("Sysmon attribution requested but wevtutil is unavailable")

    return NullAttributor()
