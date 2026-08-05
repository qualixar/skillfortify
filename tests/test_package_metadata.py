"""The package must not contradict its own packaging metadata.

Licence and authorship are read programmatically and are asserted in ASBOM
output, so every self-reported identity field is pinned here to its single
source of truth in pyproject.toml.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import skillfortify

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


@pytest.fixture(scope="module")
def declared() -> dict:
    if not PYPROJECT.is_file():  # pragma: no cover - installed without sources
        pytest.skip("pyproject.toml not present in this layout")
    return tomllib.loads(PYPROJECT.read_text())["project"]


def test_license_matches_pyproject(declared):
    """``skillfortify.__license__`` must equal the declared license."""
    assert skillfortify.__license__ == declared["license"]


def test_license_matches_license_file(declared):
    """The LICENSE file must be the license the project claims to ship under."""
    license_file = PYPROJECT.parent / "LICENSE"
    if not license_file.is_file():  # pragma: no cover - installed without sources
        pytest.skip("LICENSE not present in this layout")

    text = license_file.read_text()

    assert "Elastic License 2.0" in text
    assert declared["license"] == "Elastic-2.0"


def test_benchmark_subtree_declares_its_own_license():
    """The benchmark ships MIT so others may reuse the corpus; keep that explicit."""
    benchmark_license = PYPROJECT.parent / "benchmarks" / "LICENSE"
    if not benchmark_license.is_file():  # pragma: no cover - installed without sources
        pytest.skip("benchmarks/LICENSE not present in this layout")

    assert "MIT" in benchmark_license.read_text()


def test_author_fields_match_pyproject(declared):
    """Author identity is asserted in ASBOM output, so it must not drift."""
    authors = declared.get("authors") or []
    if not authors:  # pragma: no cover - metadata shape changed
        pytest.skip("no authors declared")

    assert skillfortify.__author__ == authors[0]["name"]
    assert skillfortify.__author_email__ == authors[0]["email"]
