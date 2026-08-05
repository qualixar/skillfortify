"""Record the machine a timing result was measured on.

A wall-clock number is only checkable against the hardware that produced it,
so every timing result carries its host.
"""

from __future__ import annotations

import os
import platform
import sys
from datetime import datetime, timezone
from typing import Any

import skillfortify


def host_metadata() -> dict[str, Any]:
    """Return the platform, interpreter, and package versions for this run."""
    try:
        import pysat  # noqa: F401

        sat_available = True
    except ImportError:
        sat_available = False

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "skillfortify_version": skillfortify.__version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
        "python_hash_seed": os.environ.get("PYTHONHASHSEED", "unset"),
        "sat_solver_available": sat_available,
    }
