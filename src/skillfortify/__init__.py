"""SkillFortify: Formal analysis and supply chain security for agentic AI skills.

Part of Qualixar — The Complete Agent Development Platform.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import metadata as _package_metadata
from importlib.metadata import version as _package_version

#: Declared in pyproject.toml. Repeated here only as the fallback for a source
#: checkout with no installed distribution to read.
_DECLARED_LICENSE = "Elastic-2.0"

try:
    # Read the installed distribution's version rather than hardcoding it, so
    # a literal here cannot desync from pyproject.toml across releases.
    __version__ = _package_version("skillfortify")
except PackageNotFoundError:  # pragma: no cover - source checkout, not installed
    __version__ = "0.0.0+unknown"

try:
    # Same single source of truth as the version: the packaging metadata, so
    # what the module reports always matches what the project ships under.
    __license__ = _package_metadata("skillfortify").get("License-Expression") or (
        _package_metadata("skillfortify").get("License") or _DECLARED_LICENSE
    )
except PackageNotFoundError:  # pragma: no cover - source checkout, not installed
    __license__ = _DECLARED_LICENSE

__author__ = "Varun Pratap Bhardwaj"
__author_email__ = "varun.pratap.bhardwaj@gmail.com"

# Product provenance — embedded in all tool output (CLI, ASBOM, lockfiles).
# SHA-256 of the product identity record. Altering this changes tool output.
_PRODUCT_ID = "skillfortify"
_PRODUCT_PROVENANCE = "sf-e94b3c8b10240fab"
_QUALIXAR_PLATFORM = "Qualixar"
_QUALIXAR_URL = "https://qualixar.com"
