"""The corpus must not let a specimen's label be read off its shape.

Malicious and benign specimens come from two separate class hierarchies. When
those hierarchies disagree about anything -- a key one emits, a directory one
creates, a marker one writes twice -- the difference lines up exactly with the
label, and a scanner can post a high score without reading any content. Four
such features shipped in an earlier corpus and none was caught by review, so
the check is mechanical and runs on every build.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.metrics.leakage import find_leaks, format_report

_CORPUS = Path(__file__).resolve().parents[3] / "benchmarks"


@pytest.fixture(scope="module")
def skills_root() -> Path:
    root = _CORPUS / "skills"
    if not root.is_dir():
        pytest.skip("generated corpus is not present in this checkout")
    return root


def test_no_structural_feature_predicts_the_label(skills_root: Path):
    """No frontmatter key, path component, or marker count gives the label away."""
    leaks = find_leaks(skills_root)
    assert not leaks, format_report(leaks)


def test_both_classes_draw_names_from_one_vocabulary(skills_root: Path):
    """A name must never belong to one class alone.

    Disjoint name pools are the cheapest possible leak: a lookup table of the
    names classifies the whole corpus. Typosquatting is the sole exception --
    there the name *is* the payload, and recognising it is the scanner's job.
    """
    manifest = json.loads((_CORPUS / "manifest.json").read_text())
    malicious: set[str] = set()
    benign: set[str] = set()

    for entry in manifest["entries"]:
        path = _CORPUS / entry["path"]
        if entry["format"] == "mcp":
            names = set(json.loads(path.read_text()).get("mcpServers", {}))
        else:
            names = {path.parent.name}
        if not entry["is_malicious"]:
            benign |= names
        elif entry["attack_type"] != "A11":
            malicious |= names

    assert not malicious - benign, (
        f"names used only by malicious specimens: {sorted(malicious - benign)}"
    )
    assert not benign - malicious, (
        f"names used only by benign specimens: {sorted(benign - malicious)}"
    )


def test_specimens_share_one_installation_layout(skills_root: Path):
    """Both classes install to the same real path for a given format."""
    expected = {
        "claude": ".claude/skills",
        "openclaw": ".openclaw/skills",
        "mcp": "",
    }
    for fmt, install_root in expected.items():
        for label in ("malicious", "benign"):
            specimens = sorted((skills_root / fmt / label).iterdir())
            assert specimens, f"no specimens under {fmt}/{label}"
            for specimen in specimens:
                if fmt == "mcp":
                    assert (specimen / ".mcp.json").is_file(), specimen
                else:
                    root = specimen / install_root
                    assert root.is_dir(), f"{specimen} is missing {install_root}"
                    assert list(root.glob("*/SKILL.md")), specimen
