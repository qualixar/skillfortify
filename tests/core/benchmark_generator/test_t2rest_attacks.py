"""Stage 6 Track T2-rest — A2-A13 attack pattern parametrized tests (LLD-02 §§7.2-7.13).

Parametrized across all 13 attack types. A1 already implemented (passes from T2).
A2-A13 are RED until implemented.

Tests cover per-attack:
- Registry metadata correctness (attack_id, parent_class, sources, supported_formats)
- Per-format instantiation produces valid RenderedSkill
- Determinism: same (spec, rng_seed) → identical bytes
- Sentinel present in output
- AST preflight clean on seeds/ package

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
# Frozen metadata from LLD-02 §4 + LLD-04
# ---------------------------------------------------------------------------

ATTACK_METADATA: dict[str, dict] = {
    "A1":  {"parent_class": "c1_DATA_EXFILTRATION",   "cls": "A1_HttpExfil"},
    "A2":  {"parent_class": "c1_DATA_EXFILTRATION",   "cls": "A2_DnsExfil"},
    "A3":  {"parent_class": "c1_DATA_EXFILTRATION",   "cls": "A3_CredentialTheft"},
    "A4":  {"parent_class": "c2_PRIVILEGE_ESCALATION", "cls": "A4_ArbitraryCodeExecution"},
    "A5":  {"parent_class": "c2_PRIVILEGE_ESCALATION", "cls": "A5_FileSystemTampering"},
    "A6":  {"parent_class": "c2_PRIVILEGE_ESCALATION", "cls": "A6_PrivilegeEscalation"},
    "A7":  {"parent_class": "c1_DATA_EXFILTRATION",   "cls": "A7_SteganographicExfiltration"},
    "A8":  {"parent_class": "c3_PROMPT_INJECTION",     "cls": "A8_PromptInjection"},
    "A9":  {"parent_class": "c1_DATA_EXFILTRATION",   "cls": "A9_ReverseShell"},
    "A10": {"parent_class": "c2_PRIVILEGE_ESCALATION", "cls": "A10_CryptocurrencyMining"},
    "A11": {"parent_class": "c5_TYPOSQUATTING",        "cls": "A11_Typosquatting"},
    "A12": {"parent_class": "c4_DEPENDENCY_CONFUSION", "cls": "A12_DependencyConfusion"},
    "A13": {"parent_class": "c1_DATA_EXFILTRATION",   "cls": "A13_EncodedPayload"},
}

ALL_ATTACK_IDS = sorted(ATTACK_METADATA.keys(), key=lambda x: int(x[1:]))


def _get_pattern(attack_id: str):
    """Import and return the pattern instance from PATTERN_REGISTRY."""
    from benchmarks.generator.seeds import PATTERN_REGISTRY
    return PATTERN_REGISTRY[attack_id]


def _make_spec(attack_id: str, fmt: str, idx: int = 1) -> SkillSpec:
    meta = ATTACK_METADATA[attack_id]
    padded = f"A{int(attack_id[1:]):02d}"
    return SkillSpec(
        skill_id=f"{fmt}_mal_{padded}_{idx:03d}",
        format=fmt,
        is_malicious=True,
        attack_type=attack_id,
        parent_class=meta["parent_class"],
        benign_category=None,
        skill_index=idx,
        obfuscation_level="L1",
    )


# ---------------------------------------------------------------------------
# Test 1 — Registry metadata (parametrized over all 13)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack_id", ALL_ATTACK_IDS)
def test_attack_registry_metadata(attack_id: str):
    """LLD-02 §4: each pattern's metadata matches the frozen table."""
    pattern = _get_pattern(attack_id)
    meta = ATTACK_METADATA[attack_id]

    assert pattern.attack_id == attack_id
    assert pattern.parent_class == meta["parent_class"]
    assert len(pattern.sources) >= 1
    assert isinstance(pattern.supported_formats(), frozenset)
    assert len(pattern.supported_formats()) >= 1


# ---------------------------------------------------------------------------
# Test 2 — Claude format produces valid .md (parametrized over all 13)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack_id", ALL_ATTACK_IDS)
def test_attack_claude_produces_valid_md(attack_id: str):
    """Each attack pattern produces parseable Claude markdown with frontmatter."""
    pattern = _get_pattern(attack_id)
    if "claude" not in pattern.supported_formats():
        pytest.skip(f"{attack_id} does not support claude format")

    spec = _make_spec(attack_id, "claude", 1)
    rng = DeterministicRNG(42, f"test::claude::mal::{attack_id}::001")
    result = pattern.instantiate(spec, rng)

    assert isinstance(result, RenderedSkill)
    assert result.format_extension == ".md"
    text = result.content_bytes.decode("utf-8")
    assert "---" in text


# ---------------------------------------------------------------------------
# Test 3 — MCP format produces valid JSON (parametrized over all 13)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack_id", ALL_ATTACK_IDS)
def test_attack_mcp_produces_valid_json(attack_id: str):
    """Each attack pattern produces parseable MCP JSON with mcpServers."""
    pattern = _get_pattern(attack_id)
    if "mcp" not in pattern.supported_formats():
        pytest.skip(f"{attack_id} does not support mcp format")

    spec = _make_spec(attack_id, "mcp", 1)
    rng = DeterministicRNG(42, f"test::mcp::mal::{attack_id}::001")
    result = pattern.instantiate(spec, rng)

    assert isinstance(result, RenderedSkill)
    assert result.format_extension == ".json"
    parsed = json.loads(result.content_bytes.decode("utf-8"))
    assert "mcpServers" in parsed


# ---------------------------------------------------------------------------
# Test 4 — OpenClaw format produces valid YAML (parametrized over all 13)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack_id", ALL_ATTACK_IDS)
def test_attack_openclaw_produces_valid_yaml(attack_id: str):
    """Each attack pattern produces parseable OpenClaw YAML."""
    pattern = _get_pattern(attack_id)
    if "openclaw" not in pattern.supported_formats():
        pytest.skip(f"{attack_id} does not support openclaw format")

    spec = _make_spec(attack_id, "openclaw", 1)
    rng = DeterministicRNG(42, f"test::openclaw::mal::{attack_id}::001")
    result = pattern.instantiate(spec, rng)

    assert isinstance(result, RenderedSkill)
    assert result.format_extension == ".yaml"
    text = result.content_bytes.decode("utf-8")
    lines = [l for l in text.split("\n") if not l.startswith("# SKILLFORTIFYBENCH")]
    parsed = yaml.safe_load("\n".join(lines))
    assert parsed is not None


# ---------------------------------------------------------------------------
# Test 5 — Determinism (parametrized over all 13 × 3 formats)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack_id", ALL_ATTACK_IDS)
def test_attack_determinism(attack_id: str):
    """Identical (spec, rng_seed) → identical content_bytes for all supported formats."""
    pattern = _get_pattern(attack_id)
    for fmt in pattern.supported_formats():
        spec = _make_spec(attack_id, fmt, 1)
        rng_a = DeterministicRNG(42, f"det::{fmt}::{attack_id}::001")
        rng_b = DeterministicRNG(42, f"det::{fmt}::{attack_id}::001")
        result_a = pattern.instantiate(spec, rng_a)
        result_b = pattern.instantiate(spec, rng_b)
        assert result_a.content_bytes == result_b.content_bytes, (
            f"Determinism failed: {attack_id} format={fmt}"
        )


# ---------------------------------------------------------------------------
# Test 6 — Sentinel present (parametrized over all 13)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack_id", ALL_ATTACK_IDS)
def test_attack_sentinel_present(attack_id: str):
    """SKILLFORTIFYBENCH:INERT sentinel must appear in every skill output."""
    pattern = _get_pattern(attack_id)
    for fmt in pattern.supported_formats():
        spec = _make_spec(attack_id, fmt, 1)
        rng = DeterministicRNG(42, f"sentinel::{fmt}::{attack_id}::001")
        result = pattern.instantiate(spec, rng)
        text = result.content_bytes.decode("utf-8")
        assert "SKILLFORTIFYBENCH:INERT" in text, (
            f"Missing sentinel in {attack_id} format={fmt}"
        )


# ---------------------------------------------------------------------------
# Test 7 — Full registry has all 13 patterns
# ---------------------------------------------------------------------------

def test_pattern_registry_has_all_13():
    """PATTERN_REGISTRY must contain exactly A1..A13."""
    from benchmarks.generator.seeds import PATTERN_REGISTRY

    expected = {f"A{i}" for i in range(1, 14)}
    assert set(PATTERN_REGISTRY.keys()) == expected, (
        f"Missing: {expected - set(PATTERN_REGISTRY.keys())}"
    )
