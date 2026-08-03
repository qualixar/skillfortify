"""SkillFortify: Formal analysis and supply chain security for agentic AI skills.

Part of Qualixar — The Complete Agent Development Platform.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _package_version

try:
    # Read the installed distribution's version rather than hardcoding it.
    # A literal here silently desyncs from pyproject.toml on every release --
    # the published 0.4.3 reported itself as 0.3.3 in both the Python API and
    # `skillfortify --version` because of exactly that.
    __version__ = _package_version("skillfortify")
except PackageNotFoundError:  # pragma: no cover - source checkout, not installed
    __version__ = "0.0.0+unknown"
__author__ = "Varun Pratap Bhardwaj"
__author_email__ = "varun.pratap.bhardwaj@gmail.com"
__license__ = "MIT"

# Product provenance — embedded in all tool output (CLI, ASBOM, lockfiles).
# SHA-256 of the product identity record. Altering this changes tool output.
_PRODUCT_ID = "skillfortify"
_PRODUCT_PROVENANCE = "sf-e94b3c8b10240fab"
_QUALIXAR_PLATFORM = "Qualixar"
_QUALIXAR_URL = "https://qualixar.com"
