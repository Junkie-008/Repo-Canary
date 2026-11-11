"""Central path configuration for the Ransomware 207 lab.

The documented lab layout is C:\\RansomwareLab, so that stays the default.
Every path can be overridden with an environment variable, which lets the
project run from a checkout (tests, another PC) without changing the code.

Environment variables:

    REPO_CANARY_LAB             lab root                (default C:\\RansomwareLab)
    REPO_CANARY_TEST_DIR        folder the engine watches
    REPO_CANARY_MONITORED_DIR   folder used by the simple monitors
    REPO_CANARY_FINDINGS        findings.json location
"""

import os
from pathlib import Path

DEFAULT_LAB_ROOT = r"C:\RansomwareLab"


def _path(env_var, default):
    return Path(os.environ.get(env_var, default)).expanduser()


LAB_ROOT = _path("REPO_CANARY_LAB", DEFAULT_LAB_ROOT)

MONITORED_DIR = _path("REPO_CANARY_MONITORED_DIR", LAB_ROOT / "monitored")

TEST_DIR = _path("REPO_CANARY_TEST_DIR", LAB_ROOT / "testdata")

FINDINGS_FILE = _path("REPO_CANARY_FINDINGS", LAB_ROOT / "findings.json")
