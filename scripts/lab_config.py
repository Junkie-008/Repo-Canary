"""Central path configuration for Repo-Canary.

The documented lab layout is ``C:\\RansomwareLab``, so that stays the default.
Every path can be overridden with an environment variable, which lets the
project run from a checkout, a container, or another PC without changing code.

Environment variables:

    REPO_CANARY_LAB             lab root                 (default C:\\RansomwareLab)
    REPO_CANARY_TEST_DIR        folder the engine watches
    REPO_CANARY_MONITORED_DIR   folder used by the simple monitors
    REPO_CANARY_DB              SQLite database path
    REPO_CANARY_FINDINGS        legacy findings.json (migration source)
    REPO_CANARY_REPORTS         PDF incident report folder
    REPO_CANARY_HASHES          local SHA-256 feed
    REPO_CANARY_LOG             error log path
"""

import os
from pathlib import Path

DEFAULT_LAB_ROOT = r"C:\RansomwareLab"

LAB_MARKER = ".repo-canary-lab"


def _path(env_var, default):
    return Path(os.environ.get(env_var, default)).expanduser()


LAB_ROOT = _path("REPO_CANARY_LAB", DEFAULT_LAB_ROOT)

MONITORED_DIR = _path("REPO_CANARY_MONITORED_DIR", LAB_ROOT / "monitored")

TEST_DIR = _path("REPO_CANARY_TEST_DIR", LAB_ROOT / "testdata")

DB_FILE = _path("REPO_CANARY_DB", LAB_ROOT / "canary.db")

# Legacy JSON store. Read once on first start and migrated into DB_FILE.
FINDINGS_FILE = _path("REPO_CANARY_FINDINGS", LAB_ROOT / "findings.json")

REPORTS_DIR = _path("REPO_CANARY_REPORTS", LAB_ROOT / "reports")

KNOWN_HASHES_FILE = _path("REPO_CANARY_HASHES", LAB_ROOT / "known_hashes.txt")

ERROR_LOG = _path("REPO_CANARY_LOG", LAB_ROOT / "error_log.txt")
