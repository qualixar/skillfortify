"""Stage 6 Track T3 — Benign category generator tests (LLD-03).

8 tests covering:
- Registry completeness (1)
- Per-format output validity for file_management (3)
- Determinism (1)
- Sentinel placement (1)
- All 5 categories produce correct category_id (1)
- AST preflight stays clean (1)

INERT TEXT ONLY. Generated skills are NEVER executed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from benchmarks.generator.core import RenderedSkill, SkillSpec
from benchmarks.generator.rng import DeterministicRNG


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_benign_spec(fmt: str, category: str, idx: int = 1) -> SkillSpec:
    cat_num = {
        "file_management": 1, "data_transformation": 2,
        "api_integration": 3, "development_tooling": 4,
        "system_information": 5,
    }[category]
    return SkillSpec(
        skill_id=f"{fmt}_ben_cat{cat_num}_{idx:03d}",
        format=fmt,
        is_malicious=False,
        attack_type="benign",
        parent_class="benign",
        benign_category=category,
        skill_index=idx,
        obfuscation_level=None,
    )


def _make_rng(label: str = "test::benign::001") -> DeterministicRNG:
    return DeterministicRNG(42, label)


# ---------------------------------------------------------------------------
# Test 1 — Registry completeness
# ---------------------------------------------------------------------------

def test_benign_registry_has_all_5_categories():
    """LLD-03 §3: BENIGN_REGISTRY must contain exactly the 5 canonical categories."""
    from benchmarks.generator.benign import BENIGN_REGISTRY
    from benchmarks.generator.config import BENIGN_CATEGORIES

    assert set(BENIGN_REGISTRY.keys()) == set(BENIGN_CATEGORIES), (
        f"Expected {set(BENIGN_CATEGORIES)}, got {set(BENIGN_REGISTRY.keys())}"
    )
    assert len(BENIGN_REGISTRY) == 5


# ---------------------------------------------------------------------------
# Test 2-4 — file_management per-format output
# ---------------------------------------------------------------------------

def test_file_management_claude_produces_valid_md():
    """LLD-03 §6.1: file_management Claude output parses as markdown with frontmatter."""
    from benchmarks.generator.benign import BENIGN_REGISTRY

    cat = BENIGN_REGISTRY["file_management"]
    spec = _make_benign_spec("claude", "file_management", 1)
    rng = _make_rng("test::claude::ben::file_management::001")
    result = cat.instantiate(spec, rng)

    assert isinstance(result, RenderedSkill)
    assert result.format_extension == ".md"
    text = result.content_bytes.decode("utf-8")
    assert "---" in text, "Claude benign skill must have YAML frontmatter"
    assert result.spec.is_malicious is False


def test_file_management_mcp_produces_valid_json():
    """LLD-03 §6.1: file_management MCP output parses as JSON with mcpServers."""
    from benchmarks.generator.benign import BENIGN_REGISTRY

    cat = BENIGN_REGISTRY["file_management"]
    spec = _make_benign_spec("mcp", "file_management", 1)
    rng = _make_rng("test::mcp::ben::file_management::001")
    result = cat.instantiate(spec, rng)

    assert isinstance(result, RenderedSkill)
    assert result.format_extension == ".json"
    parsed = json.loads(result.content_bytes.decode("utf-8"))
    assert "mcpServers" in parsed


def test_file_management_openclaw_produces_valid_yaml():
    """LLD-03 §6.1: file_management OpenClaw output parses as YAML."""
    from benchmarks.generator.benign import BENIGN_REGISTRY

    cat = BENIGN_REGISTRY["file_management"]
    spec = _make_benign_spec("openclaw", "file_management", 1)
    rng = _make_rng("test::openclaw::ben::file_management::001")
    result = cat.instantiate(spec, rng)

    assert isinstance(result, RenderedSkill)
    assert result.format_extension == ".yaml"
    text = result.content_bytes.decode("utf-8")
    lines = [l for l in text.split("\n") if not l.startswith("# SKILLFORTIFYBENCH")]
    parsed = yaml.safe_load("\n".join(lines))
    assert parsed is not None


# ---------------------------------------------------------------------------
# Test 5 — Determinism
# ---------------------------------------------------------------------------

def test_benign_determinism_same_seed_same_bytes():
    """Two calls with same (spec, rng_seed) → identical content_bytes for all formats."""
    from benchmarks.generator.benign import BENIGN_REGISTRY

    cat = BENIGN_REGISTRY["file_management"]
    for fmt in ("claude", "mcp", "openclaw"):
        spec = _make_benign_spec(fmt, "file_management", 3)
        rng_a = DeterministicRNG(42, f"det::test::{fmt}::ben::fm::003")
        rng_b = DeterministicRNG(42, f"det::test::{fmt}::ben::fm::003")
        result_a = cat.instantiate(spec, rng_a)
        result_b = cat.instantiate(spec, rng_b)
        assert result_a.content_bytes == result_b.content_bytes, (
            f"Determinism failed for benign format={fmt}"
        )


# ---------------------------------------------------------------------------
# Test 6 — Sentinel present
# ---------------------------------------------------------------------------

def test_benign_sentinel_present_all_formats():
    """LLD-02 §5 + LLD-03 §5.12: sentinel must be present in benign skills too."""
    from benchmarks.generator.benign import BENIGN_REGISTRY

    cat = BENIGN_REGISTRY["file_management"]
    for fmt in ("claude", "mcp", "openclaw"):
        spec = _make_benign_spec(fmt, "file_management", 1)
        rng = _make_rng(f"test::sentinel::benign::{fmt}::fm::001")
        result = cat.instantiate(spec, rng)
        text = result.content_bytes.decode("utf-8")
        assert "SKILLFORTIFYBENCH:INERT" in text, (
            f"Benign {fmt} skill missing SKILLFORTIFYBENCH:INERT sentinel"
        )


# ---------------------------------------------------------------------------
# Test 7 — All 5 categories produce correct category_id
# ---------------------------------------------------------------------------

def test_all_5_categories_correct_category_id():
    """Each registered category's category_id matches its registry key."""
    from benchmarks.generator.benign import BENIGN_REGISTRY

    for key, cat in BENIGN_REGISTRY.items():
        assert cat.category_id == key, (
            f"Category {key} has mismatched category_id={cat.category_id}"
        )
        assert cat.supported_formats() == frozenset({"claude", "mcp", "openclaw"})


# ---------------------------------------------------------------------------
# Test 8 — AST preflight stays clean
# ---------------------------------------------------------------------------

def test_benign_ast_preflight_clean():
    """AST scan of benign/ package must return zero violations."""
    from benchmarks.generator.preflight import ast_scan_package

    benign_root = Path(__file__).resolve().parents[3] / "benchmarks" / "generator" / "benign"
    assert benign_root.exists(), f"benign/ package not found at {benign_root}"

    violations = ast_scan_package(benign_root)
    assert violations == [], (
        f"AST scan found violations in benign/ package: "
        f"{[(v.rule, v.file, v.line) for v in violations]}"
    )
