"""Local SHA-256 threat intelligence.

The feed is a plain text file, one entry per line::

    # comment
    <64-hex sha256>
    <64-hex sha256>,<label>
    <64-hex sha256> <label>

Matching a hash upgrades a finding to ``Confirmed Ransomware``. Hashing is
only performed on alert-triggering files (not every file event), streams in
1 MiB chunks, and is cached by ``(path, size, mtime)``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import stat
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Optional

from models import IntelResult

logger = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024
CACHE_SIZE = 512
RELOAD_CHECK_SECONDS = 5.0
DEFAULT_MAX_BYTES = 256 * 1024 * 1024

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


class ThreatIntel:
    def __init__(
        self,
        hash_file: Optional[Path | str],
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ):
        self.hash_file = Path(hash_file) if hash_file else None
        self.max_bytes = max_bytes

        self._hashes: dict[str, str] = {}
        self._mtime_ns: Optional[int] = None
        self._last_check = 0.0
        self._cache: OrderedDict[tuple[str, int, int], Optional[str]] = OrderedDict()
        # Re-entrant: check() calls _result_for() while holding the lock.
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Feed
    # ------------------------------------------------------------------

    def load(self) -> int:
        """Load the feed into memory. Returns the number of valid hashes."""

        if self.hash_file is None:
            return 0

        try:
            stat_result = self.hash_file.stat()
        except OSError:
            logger.warning("Threat-intel feed not found: %s", self.hash_file)
            return 0

        entries: dict[str, str] = {}

        try:
            with self.hash_file.open("r", encoding="utf-8", errors="replace") as file:
                for line in file:
                    parsed = self._parse_line(line)
                    if parsed:
                        digest, label = parsed
                        entries[digest] = label
        except OSError as error:
            logger.error("Could not read threat-intel feed: %s", error)
            return 0

        with self._lock:
            self._hashes = entries
            self._mtime_ns = stat_result.st_mtime_ns
            self._cache.clear()

        logger.info("Loaded %d threat-intel hashes", len(entries))
        return len(entries)

    def entries(self) -> list[tuple[str, str, str]]:
        """Return ``(sha256, label, source)`` tuples for the DB mirror."""

        source = str(self.hash_file) if self.hash_file else ""

        with self._lock:
            return [
                (digest, label, source)
                for digest, label in self._hashes.items()
            ]

    @staticmethod
    def _parse_line(line: str) -> Optional[tuple[str, str]]:
        text = line.strip()

        if not text or text.startswith("#"):
            return None

        if "," in text:
            digest, label = text.split(",", 1)
        else:
            parts = text.split(None, 1)
            digest = parts[0]
            label = parts[1] if len(parts) > 1 else "known-malicious"

        digest = digest.strip().lower()
        label = (label.strip() or "known-malicious")[:200]

        if not _SHA256.match(digest):
            return None

        return digest, label

    def _maybe_reload(self) -> None:
        if self.hash_file is None:
            return

        now = time.time()

        with self._lock:
            if now - self._last_check < RELOAD_CHECK_SECONDS:
                return
            self._last_check = now

        try:
            current = self.hash_file.stat().st_mtime_ns
        except OSError:
            return

        if current != self._mtime_ns:
            logger.info("Threat-intel feed changed; reloading")
            self.load()

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def check(self, path: str) -> IntelResult:
        """Hash one file and check it against the in-memory feed."""

        self._maybe_reload()

        try:
            normalized = os.path.normcase(os.path.abspath(path))
            stat_result = os.stat(normalized)
        except OSError as error:
            return IntelResult(error=f"stat failed: {error}")

        if not stat.S_ISREG(stat_result.st_mode):
            return IntelResult(error="not a regular file")

        if stat_result.st_size > self.max_bytes:
            return IntelResult(error="file exceeds hash size limit")

        cache_key = (normalized, stat_result.st_size, stat_result.st_mtime_ns)

        with self._lock:
            if cache_key in self._cache:
                self._cache.move_to_end(cache_key)
                digest = self._cache[cache_key]
                return self._result_for(digest)

        digest = self._hash_file(Path(normalized))

        if digest is None:
            return IntelResult(error="read failed")

        with self._lock:
            self._cache[cache_key] = digest
            self._cache.move_to_end(cache_key)

            while len(self._cache) > CACHE_SIZE:
                self._cache.popitem(last=False)

        return self._result_for(digest)

    def _result_for(self, digest: Optional[str]) -> IntelResult:
        if digest is None:
            return IntelResult(error="read failed")

        with self._lock:
            label = self._hashes.get(digest)

        return IntelResult(sha256=digest, label=label)

    @staticmethod
    def _hash_file(path: Path) -> Optional[str]:
        digest = hashlib.sha256()

        try:
            with path.open("rb") as file:
                for chunk in iter(lambda: file.read(CHUNK_SIZE), b""):
                    digest.update(chunk)
        except OSError as error:
            logger.warning("Could not hash %s: %s", path, error)
            return None

        return digest.hexdigest()
