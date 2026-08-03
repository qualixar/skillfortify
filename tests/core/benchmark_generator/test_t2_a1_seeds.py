"""Stage 6 Track T2 — A1 HTTP exfiltration seed tests (LLD-02 §7.1).

10 RED tests covering:
- Registry metadata (1)
- Per-format instantiation produces valid output (3)
- Determinism (1)
- MCP variant 10 miss (1)
- Sentinel placement per format (3)
- AST preflight stays clean (1)

INERT TEXT ONLY. Generated skills are NEVER executed.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from benchmarks.generator.core import RenderedSkill, SkillSpec
from benchmarks.generator.rng import DeterministicRNG

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_spec(fmt: str, idx: int = 1, *, is_canary: bool = False) -> SkillSpec:
    """Build a minimal malicious A1 SkillSpec for testing."""
    return SkillSpec(
        skill_id=f"{fmt}_mal_A01_{idx:03d}",
        format=fmt,
        is_malicious=True,
        attack_type="A1",
        parent_class="c1_DATA_EXFILTRATION",
        benign_category=None,
        skill_index=idx,
        obfuscation_level="L1",
        is_canary=is_canary,
    )


def _make_rng(label: str = "test::A1::001") -> DeterministicRNG:
    return DeterministicRNG(42, label)


# ---------------------------------------------------------------------------
# Test 1 — Registry metadata
# ---------------------------------------------------------------------------

def test_a1_registry_metadata():
    """§7.1.1: A1_HttpExfil class attributes match LLD-02 frozen metadata table."""
    from benchmarks.generator.seeds.a1_http_exfil import A1_HttpExfil

    a1 = A1_HttpExfil()
    assert a1.attack_id == "A1"
    assert a1.parent_class == "c1_DATA_EXFILTRATION"
    assert a1.sources == ("ClawHavoc (Koi Security / Yomtov, Feb 2026)",)
    assert a1.supported_formats() == frozenset({"claude", "mcp", "openclaw"})
    assert 1 in a1.obfuscation_levels_supported
    assert 4 in a1.obfuscation_levels_supported


# ---------------------------------------------------------------------------
# Test 2-4 — Per-format instantiation produces valid output
# ---------------------------------------------------------------------------

def test_a1_instantiate_claude_produces_valid_md():
    """§7.1.3: Claude instantiation returns RenderedSkill with parseable .md."""
    from benchmarks.generator.seeds.a1_http_exfil import A1_HttpExfil

    a1 = A1_HttpExfil()
    spec = _make_spec("claude", 1)
    rng = _make_rng("test::claude::mal::A1::001")
    result = a1.instantiate(spec, rng)

    assert isinstance(result, RenderedSkill)
    assert result.format_extension == ".md"
    assert result.filename.endswith(".md")
    text = result.content_bytes.decode("utf-8")
    assert "---" in text, "Claude skill must have YAML frontmatter"
    assert result.spec.skill_id == spec.skill_id


def test_a1_instantiate_mcp_produces_valid_json():
    """§7.1.4: MCP instantiation returns RenderedSkill with parseable JSON."""
    from benchmarks.generator.seeds.a1_http_exfil import A1_HttpExfil

    a1 = A1_HttpExfil()
    spec = _make_spec("mcp", 1)
    rng = _make_rng("test::mcp::mal::A1::001")
    result = a1.instantiate(spec, rng)

    assert isinstance(result, RenderedSkill)
    assert result.format_extension == ".json"
    parsed = json.loads(result.content_bytes.decode("utf-8"))
    assert "mcpServers" in parsed, "MCP skill must have mcpServers key"


def test_a1_instantiate_openclaw_produces_a_skill_md():
    """An OpenClaw specimen is a ``SKILL.md`` under the runtime's load path.

    OpenClaw loads ``<root>/.openclaw/skills/<name>/SKILL.md`` with YAML
    frontmatter. Emitting a manifest under some other name would leave the
    corpus unable to exercise the discovery path a real scan takes.
    """
    from benchmarks.generator.seeds.a1_http_exfil import A1_HttpExfil

    a1 = A1_HttpExfil()
    spec = _make_spec("openclaw", 1)
    rng = _make_rng("test::openclaw::mal::A1::001")
    result = a1.instantiate(spec, rng)

    assert isinstance(result, RenderedSkill)
    assert result.format_extension == ".md"
    assert result.filename.endswith("/SKILL.md")
    assert ".openclaw/skills/" in result.filename

    text = result.content_bytes.decode("utf-8")
    assert text.startswith("---\n"), "SKILL.md must open with YAML frontmatter"
    frontmatter = yaml.safe_load(text.split("---\n")[1])
    assert frontmatter["name"]
    assert frontmatter["description"]


# ---------------------------------------------------------------------------
# Test 5 — Determinism
# ---------------------------------------------------------------------------

def test_a1_determinism_same_seed_same_bytes():
    """§B.3 Principle 2: identical (spec, rng_seed) → identical content_bytes."""
    from benchmarks.generator.seeds.a1_http_exfil import A1_HttpExfil

    a1 = A1_HttpExfil()
    for fmt in ("claude", "mcp", "openclaw"):
        spec = _make_spec(fmt, 3)
        rng_a = DeterministicRNG(42, f"det::test::{fmt}::A1::003")
        rng_b = DeterministicRNG(42, f"det::test::{fmt}::A1::003")
        result_a = a1.instantiate(spec, rng_a)
        result_b = a1.instantiate(spec, rng_b)
        assert result_a.content_bytes == result_b.content_bytes, (
            f"Determinism failed for format={fmt}: bytes differ"
        )


# ---------------------------------------------------------------------------
# Test 6 — MCP variant 10 miss
# ---------------------------------------------------------------------------

def test_a1_mcp_variant_10_miss_no_literal_url():
    """§7.1.6: MCP variant 10 contains no literal http:// or https:// → MISS."""
    from benchmarks.generator.seeds.a1_http_exfil import A1_HttpExfil

    a1 = A1_HttpExfil()
    spec = _make_spec("mcp", 10)
    rng = _make_rng("test::mcp::mal::A1::010")
    result = a1.instantiate(spec, rng)

    text = result.content_bytes.decode("utf-8")
    assert "http://" not in text and "https://" not in text, (
        "MCP variant 10 must NOT contain literal http(s):// URL — it's an intentional MISS"
    )


# ---------------------------------------------------------------------------
# Test 7-9 — Sentinel placement per format
# ---------------------------------------------------------------------------

def test_a1_sentinel_claude_html_comment():
    """§5.1: Claude sentinel is an HTML comment after frontmatter closing ---."""
    from benchmarks.generator.seeds.a1_http_exfil import A1_HttpExfil

    a1 = A1_HttpExfil()
    spec = _make_spec("claude", 1)
    rng = _make_rng("test::sentinel::claude::A1::001")
    result = a1.instantiate(spec, rng)
    text = result.content_bytes.decode("utf-8")

    assert "<!-- SKILLFORTIFYBENCH:INERT" in text, (
        "Claude skill must contain SKILLFORTIFYBENCH:INERT sentinel as HTML comment"
    )


def test_a1_sentinel_mcp_key_first_in_json():
    """§5.1: MCP sentinel key '_skillfortifybench_inert' present and sorts first."""
    from benchmarks.generator.seeds.a1_http_exfil import A1_HttpExfil

    a1 = A1_HttpExfil()
    spec = _make_spec("mcp", 1)
    rng = _make_rng("test::sentinel::mcp::A1::001")
    result = a1.instantiate(spec, rng)
    parsed = json.loads(result.content_bytes.decode("utf-8"))

    assert "_skillfortifybench_inert" in parsed, (
        "MCP skill must contain _skillfortifybench_inert key"
    )
    keys = list(parsed.keys())
    assert keys[0] == "_skillfortifybench_inert", (
        f"_skillfortifybench_inert must be first key, got: {keys[:3]}"
    )


def test_a1_sentinel_openclaw_opens_the_body():
    """The inert marker is the first thing in the Markdown body.

    It appears exactly once and in the same form as every other specimen
    carries: a marker written differently for one class, or twice for one
    format, is a feature that predicts the label.
    """
    from benchmarks.generator.seeds.a1_http_exfil import A1_HttpExfil

    a1 = A1_HttpExfil()
    spec = _make_spec("openclaw", 1)
    rng = _make_rng("test::sentinel::openclaw::A1::001")
    result = a1.instantiate(spec, rng)
    text = result.content_bytes.decode("utf-8")
    body = text.split("\n---\n", 1)[1].lstrip("\n")

    assert body.startswith("<!-- SKILLFORTIFYBENCH:INERT"), (
        f"body must open with the sentinel, got: {body[:80]!r}"
    )
    assert text.count("SKILLFORTIFYBENCH:INERT") == 1


# ---------------------------------------------------------------------------
# Test 10 — AST preflight stays clean
# ---------------------------------------------------------------------------

def test_a1_ast_preflight_clean():
    """§6: AST scan of seeds/ package must return zero violations.

    Seed modules contain dangerous strings as DATA LITERALS only (not executable code).
    The AST scan distinguishes ast.Constant strings from ast.Call nodes.
    """
    from benchmarks.generator.preflight import ast_scan_package

    seeds_root = Path(__file__).resolve().parents[3] / "benchmarks" / "generator" / "seeds"
    assert seeds_root.exists(), f"seeds/ package not found at {seeds_root}"

    violations = ast_scan_package(seeds_root)
    assert violations == [], (
        f"AST scan found violations in seeds/ package (should be zero): "
        f"{[(v.rule, v.file, v.line) for v in violations]}"
    )
