"""Shared fixtures for Stage 6 Track T1 bones tests.

Scope per session-handoff 2026-04-22 §6 + LLD-01 §§1-6:
- project_root_override fixture (R-SR-8 needs output under project root)
- pythonhashseed_observed="0" passed to constructor (CLI boundary mocked)
- parser_roundtrip=False for bones (no real attack/benign realizations yet)

All fixtures are session-scoped where safe, function-scoped where isolation matters.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest


# Project root used for safe-output-root validation (R-SR-8 per LLD-01 §7.8).
# Tests write output under this directory.
PROJECT_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Absolute path to skillfortify/ (the dir containing pyproject.toml)."""
    assert (PROJECT_ROOT / "pyproject.toml").exists(), (
        f"Expected pyproject.toml at {PROJECT_ROOT}; fix PROJECT_ROOT derivation."
    )
    return PROJECT_ROOT


@pytest.fixture
def safe_output_root(tmp_path_factory, project_root: Path) -> Path:
    """Generate a project-local temp dir satisfying all 12 R-SR-* rules.

    pytest's default tmp_path lives under /private/var/... on macOS, which fails
    R-SR-8 (escape_project_root). Tests that exercise SkillWriter/run() need
    output under project_root. We use `.skfval-tmp/` per LLD-05 §3 convention.
    """
    scratch = project_root / ".skfval-tmp"
    scratch.mkdir(exist_ok=True)
    # Unique per-test dir (uuid4 hex) to avoid collisions across reruns / parametrize.
    out = scratch / f"sfb_t1_{uuid.uuid4().hex[:12]}"
    out.mkdir(parents=True, exist_ok=False)
    return out


@pytest.fixture
def constructor_kwargs(project_root: Path, safe_output_root: Path) -> dict:
    """Minimal kwargs accepted by BenchmarkGenerator for bones tests.

    Matches LLD-01 §6.11 constructor signature. Tests may override individual keys.
    """
    return {
        "output_root": safe_output_root,
        "seed": 42,
        "pythonhashseed_observed": "0",
        "project_root_override": project_root,
        "parser_roundtrip": False,
    }
