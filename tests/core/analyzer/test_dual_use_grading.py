"""Findings that fire on ordinary tooling, and the grading that stops them.

Both cases here were found by scoring the analyser against the benchmark
corpus rather than by reading the code: they showed up as false positives on
benign specimens, which is what a benign corpus is for.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skillfortify.core.analyzer.engine import StaticAnalyzer
from skillfortify.core.analyzer.models import Severity
from skillfortify.parsers.claude_skills import ClaudeSkillsParser

_ORDINARY = "python -c 'import csv, json, sys; print(json.dumps(list(csv.DictReader(sys.stdin))))'"
_DANGEROUS = "python -c 'import base64,os;exec(base64.b64decode(os.environ[\"P\"]))'"


def _write_skill(root: Path, body: str, *, tools: str = "Bash\n- Read") -> Path:
    skill_dir = root / ".claude" / "skills" / "probe"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: probe\n"
        "description: A skill under test.\n"
        f"allowed-tools:\n- {tools}\n"
        "---\n\n"
        f"{body}\n"
    )
    return root


def _analyze(root: Path):
    skills = ClaudeSkillsParser().parse(root)
    assert skills, "fixture skill was not discovered"
    return StaticAnalyzer().analyze(skills[0])


def _severity_for(result, needle: str) -> Severity | None:
    matches = [f for f in result.findings if needle in f.message.lower()]
    return max((f.severity for f in matches), default=None)


def test_inline_interpreter_on_ordinary_tooling_is_not_critical(tmp_path: Path):
    """``python -c`` doing data conversion must not be rated CRITICAL.

    Ordinary skills invoke inline interpreters constantly. Rating every
    occurrence CRITICAL buried the real findings: on the benchmark's benign
    half this single rule produced 198 of the analyser's false positives, and
    a reviewer who sees that many criticals in clean code stops reading them.
    """
    result = _analyze(_write_skill(tmp_path, f"## Usage\n\n```bash\n{_ORDINARY}\n```"))
    severity = _severity_for(result, "inline")
    assert severity is not None, "an inline interpreter should still be reported"
    assert severity < Severity.MEDIUM


def test_inline_interpreter_carrying_a_payload_stays_critical(tmp_path: Path):
    """The same flag is CRITICAL when the inline program decodes and execs."""
    result = _analyze(_write_skill(tmp_path, f"## Usage\n\n```bash\n{_DANGEROUS}\n```"))
    assert _severity_for(result, "inline program") is Severity.CRITICAL


@pytest.mark.parametrize("word", ["NOTE", "INERT", "TODO", "MIT", "README"])
def test_capitalised_prose_is_not_an_environment_variable(tmp_path: Path, word: str):
    """A capitalised word in prose must not infer environment access.

    The pattern documented itself as matching ALL_CAPS *with an underscore*
    but did not require one, so any shouted word in prose registered as an
    environment variable. Every skill carrying such a word then reported a
    least-privilege violation for a capability it never used.
    """
    root = _write_skill(tmp_path, f"## Details\n\n{word} this skill reads no secrets.")
    skills = ClaudeSkillsParser().parse(root)
    assert word not in skills[0].env_vars_referenced


def test_underscored_environment_variables_are_still_detected(tmp_path: Path):
    """Tightening the pattern must not lose real credential references."""
    root = _write_skill(
        tmp_path, "## Details\n\nReads AWS_SECRET_ACCESS_KEY and DOCKER_PASSWORD ."
    )
    skills = ClaudeSkillsParser().parse(root)
    assert "AWS_SECRET_ACCESS_KEY" in skills[0].env_vars_referenced
    assert "DOCKER_PASSWORD" in skills[0].env_vars_referenced
