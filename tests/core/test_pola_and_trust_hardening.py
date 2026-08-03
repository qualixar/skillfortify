"""Regression tests for least-privilege and trust-scoring hardening.

These cases pin behaviour where silence must not be read as safety: a skill
that pre-authorises everything, a declaration written in tool vocabulary rather
than resource vocabulary, and a trust level whose name asserts a kind of
verification the signals do not support.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skillfortify.core.analyzer import StaticAnalyzer
from skillfortify.core.trust import TrustEngine, TrustLevel, TrustSignals
from skillfortify.parsers.base import ParsedSkill

_DANGEROUS = {"shell_commands": ["rm -rf /data", "cat ~/.ssh/id_rsa"]}


@pytest.fixture
def analyzer() -> StaticAnalyzer:
    return StaticAnalyzer()


def _analyze(analyzer: StaticAnalyzer, **kw):
    skill = ParsedSkill(
        name="probe", version="1.0", source_path=Path("/tmp/probe"), format="claude", **kw
    )
    return analyzer.analyze(skill)


def _capability_findings(result) -> list:
    return [f for f in result.findings if f.finding_type == "capability_violation"]


# ---------------------------------------------------------------------------
# Declaration vocabulary
# ---------------------------------------------------------------------------


def test_tool_name_declarations_grant_capabilities(analyzer: StaticAnalyzer) -> None:
    """``allowed-tools: Bash, Write`` must actually grant shell and filesystem.

    Declarations arrive in two vocabularies: canonical ``resource:LEVEL``
    strings, and agent tool names from frontmatter. Both must resolve to real
    grants, or a declaration the user wrote has no effect.
    """
    result = _analyze(analyzer, declared_capabilities=["Bash", "Write"], **_DANGEROUS)
    violations = [f for f in _capability_findings(result) if "violation" in f.message.lower()]
    assert not violations, f"declared tools did not grant capabilities: {violations}"


def test_unrecognised_declarations_are_reported(analyzer: StaticAnalyzer) -> None:
    """A declaration we cannot interpret must be surfaced, not dropped."""
    result = _analyze(analyzer, declared_capabilities=["definitely-not-a-tool"], **_DANGEROUS)
    assert any("unrecognised" in f.message.lower() for f in _capability_findings(result)), (
        "unparsable declaration was silently ignored"
    )


# ---------------------------------------------------------------------------
# Over-declaration
# ---------------------------------------------------------------------------


def test_wildcard_admin_declaration_is_flagged(analyzer: StaticAnalyzer) -> None:
    """``*:ADMIN`` pre-authorises everything, so POLA can never constrain it."""
    result = _analyze(analyzer, declared_capabilities=["*:ADMIN"], **_DANGEROUS)
    assert any("over-declared" in f.message.lower() for f in _capability_findings(result))


def test_broad_admin_declaration_is_flagged(analyzer: StaticAnalyzer) -> None:
    """ADMIN across several resources is self-authorisation, not least privilege."""
    result = _analyze(
        analyzer,
        declared_capabilities=["shell:ADMIN", "filesystem:ADMIN", "network:ADMIN"],
        **_DANGEROUS,
    )
    assert any("over-declared" in f.message.lower() for f in _capability_findings(result))


def test_narrow_declaration_is_not_flagged_as_over_declaration(
    analyzer: StaticAnalyzer,
) -> None:
    """A modest declaration must not trip the over-declaration check."""
    result = _analyze(analyzer, declared_capabilities=["filesystem:READ"], **_DANGEROUS)
    assert not any("over-declared" in f.message.lower() for f in _capability_findings(result))


def test_undeclared_skill_is_not_treated_as_violating(analyzer: StaticAnalyzer) -> None:
    """No declaration means no claim to violate.

    A skill that declares nothing has made no claim, so there is nothing for
    least-privilege checking to compare against. Dangerous-pattern detection
    still covers such skills.
    """
    result = _analyze(analyzer, shell_commands=["ls -la", "git status"])
    assert not _capability_findings(result)
    assert result.is_safe


# ---------------------------------------------------------------------------
# Trust levels must require the evidence their names assert
# ---------------------------------------------------------------------------


def test_undetected_skill_is_not_community_verified() -> None:
    """Absence of detection must not be reported as community verification.

    A skill the analyser found nothing in scores ``behavioral = 1.0``. Combined
    with neutral defaults that clears the community threshold numerically, but
    no community reviewed it, so the level must not claim otherwise.
    """
    signals = TrustSignals(provenance=0.5, behavioral=1.0, community=0.5, historical=0.5)
    score = TrustEngine().compute_score("undetected", "1.0", signals)
    assert score.level < TrustLevel.COMMUNITY_VERIFIED


def test_real_community_signal_still_reaches_community_level() -> None:
    """The gate must not block genuinely reviewed skills."""
    signals = TrustSignals(provenance=0.6, behavioral=1.0, community=0.9, historical=0.8)
    score = TrustEngine().compute_score("reviewed", "1.0", signals)
    assert score.level >= TrustLevel.COMMUNITY_VERIFIED


def test_formal_level_requires_provenance() -> None:
    """FORMALLY_VERIFIED requires provenance evidence above neutral."""
    signals = TrustSignals(provenance=0.5, behavioral=1.0, community=1.0, historical=1.0)
    score = TrustEngine().compute_score("no-provenance", "1.0", signals)
    assert score.level < TrustLevel.FORMALLY_VERIFIED


def test_numeric_score_is_unchanged_by_gating() -> None:
    """Gating adjusts the reported level only; the score itself is untouched."""
    signals = TrustSignals(provenance=0.5, behavioral=1.0, community=0.5, historical=0.5)
    score = TrustEngine().compute_score("undetected", "1.0", signals)
    assert score.effective_score == pytest.approx(0.65, abs=0.01)


# ---------------------------------------------------------------------------
# Confirmed malicious behaviour outranks reputation
# ---------------------------------------------------------------------------


def test_detected_malware_is_floored_at_unsigned() -> None:
    """A skill with detected dangerous content cannot hold a reassuring level."""
    signals = TrustSignals(provenance=0.5, behavioral=0.0, community=0.5, historical=0.5)
    score = TrustEngine().compute_score("malware", "1.0", signals)
    assert score.level == TrustLevel.UNSIGNED


def test_strong_publisher_cannot_launder_detected_malware() -> None:
    """Reputation must not raise the level of confirmed malicious content.

    Detection is evidence against a skill, not a missing input, so strong
    provenance and community signals must not raise its level.
    """
    signals = TrustSignals(provenance=0.95, behavioral=0.0, community=0.95, historical=0.95)
    score = TrustEngine().compute_score("well-published-malware", "1.0", signals)
    assert score.level == TrustLevel.UNSIGNED


# ---------------------------------------------------------------------------
# Integrity must cover the whole skill directory
# ---------------------------------------------------------------------------


def test_tree_integrity_detects_companion_script_tampering(tmp_path: Path) -> None:
    """Editing a companion script must change the integrity hash.

    A skill directory may ship executable scripts, so integrity must cover the
    whole directory rather than ``SKILL.md`` alone.
    """
    from skillfortify.core.lockfile import Lockfile

    skill_dir = tmp_path / "deploy"
    (skill_dir / "scripts").mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: deploy\n---\n\nRun the script.\n")
    script = skill_dir / "scripts" / "run.sh"
    script.write_text("#!/bin/sh\necho hello\n")

    before = Lockfile.compute_tree_integrity(skill_dir / "SKILL.md")
    script.write_text("#!/bin/sh\necho pwned\n")
    after = Lockfile.compute_tree_integrity(skill_dir / "SKILL.md")

    assert before != after, "companion script edit did not change the integrity hash"


def test_tree_integrity_is_stable_and_order_independent(tmp_path: Path) -> None:
    """The same tree must always hash identically."""
    from skillfortify.core.lockfile import Lockfile

    skill_dir = tmp_path / "stable"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: stable\n---\n\nBody.\n")
    (skill_dir / "a.txt").write_text("alpha")
    (skill_dir / "b.txt").write_text("bravo")

    assert Lockfile.compute_tree_integrity(skill_dir) == Lockfile.compute_tree_integrity(skill_dir)


def test_tree_integrity_detects_file_rename(tmp_path: Path) -> None:
    """Path is part of the digest, so a rename is detected like an edit."""
    from skillfortify.core.lockfile import Lockfile

    skill_dir = tmp_path / "renamed"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: renamed\n---\n\nBody.\n")
    original = skill_dir / "helper.sh"
    original.write_text("echo hi")

    before = Lockfile.compute_tree_integrity(skill_dir)
    original.rename(skill_dir / "setup.sh")
    assert Lockfile.compute_tree_integrity(skill_dir) != before
