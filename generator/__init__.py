"""benchmarks.generator — deterministic skill generator backbone.

Per LLD-01 §3 + §5.7. Version is sourced via importlib.metadata with a
'0.0.0-dev' fallback for environments where the benchmarks package is not
installed as a distribution.
"""

from __future__ import annotations

from typing import Final

try:
    from importlib.metadata import version as _pkg_version

    __version__: Final[str] = _pkg_version("benchmarks")
except Exception:  # noqa: BLE001
    __version__ = "0.0.0-dev"
