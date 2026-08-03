"""Conformance tests for the Claude Code skills parser.

These tests are written against the *upstream* Agent Skills specification as
documented at https://code.claude.com/docs/en/skills. Fixtures authored inside
a project can only confirm that project's own assumptions, so discovery is
pinned here against the published layout and against artifacts taken verbatim
from upstream.

Upstream layout (verified 2026-08-03):

===========  ====================================================
Level        Path
===========  ====================================================
Personal     ``~/.claude/skills/<skill-name>/SKILL.md``
Project      ``.claude/skills/<skill-name>/SKILL.md``
Plugin       ``<plugin>/skills/<skill-name>/SKILL.md``
Legacy       ``.claude/commands/<name>.md`` (merged into skills)
===========  ====================================================

Additional upstream behaviour exercised here: nested ``.claude/skills/``
directories below the root load as well (monorepo packages), a
``<skill-name>`` entry may be a symlink that must be followed and
de-duplicated, and ``allowed-tools`` / ``disallowed-tools`` frontmatter
declares a pre-approved tool grant -- a capability signal the analyser needs.

The final tests run against skills published upstream and, when present,
against the real skill tree on the host machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skillfortify.parsers.claude_skills import ClaudeSkillsParser


@pytest.fixture
def parser() -> ClaudeSkillsParser:
    return ClaudeSkillsParser()


def _write_skill(directory: Path, name: str, body: str = "") -> Path:
    """Write a canonical ``<skill-name>/SKILL.md`` and return its path."""
    skill_dir = directory / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text(
        f"---\nname: {name}\ndescription: Test skill {name}\n---\n\n{body}",
        encoding="utf-8",
    )
    return skill_file


# ---------------------------------------------------------------------------
# Canonical layouts
# ---------------------------------------------------------------------------


def test_project_skill_directory_is_discovered(parser: ClaudeSkillsParser, tmp_path: Path) -> None:
    """``.claude/skills/<name>/SKILL.md`` is the documented project layout."""
    _write_skill(tmp_path / ".claude" / "skills", "deploy-helper")

    assert parser.can_parse(tmp_path) is True
    skills = parser.parse(tmp_path)
    assert [s.name for s in skills] == ["deploy-helper"]


def test_multiple_skills_each_in_own_directory(parser: ClaudeSkillsParser, tmp_path: Path) -> None:
    """Each skill is its own directory; all of them must be found."""
    skills_root = tmp_path / ".claude" / "skills"
    for name in ("alpha", "bravo", "charlie"):
        _write_skill(skills_root, name)

    assert sorted(s.name for s in parser.parse(tmp_path)) == ["alpha", "bravo", "charlie"]


def test_plugin_skill_layout_is_discovered(parser: ClaudeSkillsParser, tmp_path: Path) -> None:
    """Plugin skills live at ``<plugin>/skills/<name>/SKILL.md``."""
    _write_skill(tmp_path / ".claude" / "plugins" / "some-plugin" / "skills", "plugin-skill")

    assert parser.can_parse(tmp_path) is True
    assert "plugin-skill" in [s.name for s in parser.parse(tmp_path)]


def test_nested_monorepo_skills_are_discovered(parser: ClaudeSkillsParser, tmp_path: Path) -> None:
    """Nested ``.claude/skills/`` below the root also load (monorepo packages)."""
    _write_skill(tmp_path / ".claude" / "skills", "root-skill")
    _write_skill(tmp_path / "packages" / "frontend" / ".claude" / "skills", "frontend-skill")

    found = sorted(s.name for s in parser.parse(tmp_path))
    assert found == ["frontend-skill", "root-skill"]


def test_legacy_commands_directory_is_discovered(
    parser: ClaudeSkillsParser, tmp_path: Path
) -> None:
    """``.claude/commands/*.md`` still works upstream and carries the same frontmatter."""
    commands = tmp_path / ".claude" / "commands"
    commands.mkdir(parents=True)
    (commands / "deploy.md").write_text(
        "---\ndescription: Legacy command\n---\n\nRun the deploy.\n", encoding="utf-8"
    )

    assert parser.can_parse(tmp_path) is True
    assert "deploy" in [s.name for s in parser.parse(tmp_path)]


# ---------------------------------------------------------------------------
# Negative cases -- non-skill layouts must not be treated as valid
# ---------------------------------------------------------------------------


def test_flat_markdown_in_skills_root_is_not_a_skill(
    parser: ClaudeSkillsParser, tmp_path: Path
) -> None:
    """A bare ``.claude/skills/foo.md`` is not a skill in any Claude Code version."""
    skills_dir = tmp_path / ".claude" / "skills"
    skills_dir.mkdir(parents=True)
    (skills_dir / "not-a-skill.md").write_text("# stray notes\n", encoding="utf-8")

    assert parser.can_parse(tmp_path) is False
    assert parser.parse(tmp_path) == []


def test_directory_without_skill_md_is_ignored(parser: ClaudeSkillsParser, tmp_path: Path) -> None:
    """A skill directory missing SKILL.md is not a skill."""
    (tmp_path / ".claude" / "skills" / "empty-skill").mkdir(parents=True)

    assert parser.can_parse(tmp_path) is False


# ---------------------------------------------------------------------------
# Security-relevant frontmatter
# ---------------------------------------------------------------------------


def test_allowed_tools_are_captured_as_declared_capabilities(
    parser: ClaudeSkillsParser, tmp_path: Path
) -> None:
    """``allowed-tools`` pre-approves tools without prompting -- a capability grant."""
    skill_dir = tmp_path / ".claude" / "skills" / "risky"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: risky\n"
        "description: Pre-approves shell access\n"
        "allowed-tools: Bash, Write\n"
        "---\n\nDoes things.\n",
        encoding="utf-8",
    )

    (skill,) = parser.parse(tmp_path)
    assert "Bash" in skill.declared_capabilities
    assert "Write" in skill.declared_capabilities


def test_name_defaults_to_directory_when_frontmatter_omits_it(
    parser: ClaudeSkillsParser, tmp_path: Path
) -> None:
    """Upstream: ``name`` is optional and defaults to the directory name."""
    skill_dir = tmp_path / ".claude" / "skills" / "inferred-name"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\ndescription: No explicit name\n---\n\nBody.\n", encoding="utf-8"
    )

    (skill,) = parser.parse(tmp_path)
    assert skill.name == "inferred-name"


def test_symlinked_skill_is_followed_and_not_double_counted(
    parser: ClaudeSkillsParser, tmp_path: Path
) -> None:
    """Upstream follows symlinked skill directories and loads each target once."""
    real = tmp_path / "elsewhere"
    _write_skill(real, "shared-skill")

    skills_root = tmp_path / ".claude" / "skills"
    skills_root.mkdir(parents=True)
    (skills_root / "shared-skill").symlink_to(real / "shared-skill", target_is_directory=True)
    (skills_root / "alias").symlink_to(real / "shared-skill", target_is_directory=True)

    names = [s.name for s in parser.parse(tmp_path)]
    assert names.count("shared-skill") == 1


# ---------------------------------------------------------------------------
# Conformance against upstream-authored artifacts
# ---------------------------------------------------------------------------

# Skills copied verbatim from Anthropic's public Agent Skills repository. See
# tests/fixtures/claude_code/PROVENANCE.md for the source commit and hashes.
# Unlike the host-tree check below, this runs anywhere, including CI.
_FIXTURE_ROOT = Path(__file__).parent.parent / "fixtures" / "claude_code"
_FIXTURE_SKILLS = sorted((_FIXTURE_ROOT / ".claude" / "skills").glob("*/SKILL.md"))


def test_upstream_fixtures_are_present() -> None:
    """The vendored upstream corpus must exist; silently skipping it hides drift."""
    assert _FIXTURE_SKILLS, f"no upstream fixtures under {_FIXTURE_ROOT}"
    assert (_FIXTURE_ROOT / "PROVENANCE.md").is_file()


def test_parses_every_upstream_skill(parser: ClaudeSkillsParser) -> None:
    """Every skill published by Anthropic must be discovered."""
    assert parser.can_parse(_FIXTURE_ROOT) is True

    parsed_paths = {s.source_path.resolve() for s in parser.parse(_FIXTURE_ROOT)}
    missing = [p for p in _FIXTURE_SKILLS if p.resolve() not in parsed_paths]
    assert not missing, f"{len(missing)} upstream skills not discovered: {missing}"


def test_upstream_skills_yield_usable_metadata(parser: ClaudeSkillsParser) -> None:
    """Real skills must produce the fields downstream analysis depends on."""
    skills = {s.name: s for s in parser.parse(_FIXTURE_ROOT)}

    assert "docx" in skills
    docx = skills["docx"]
    assert docx.format == "claude"
    assert docx.description.strip()
    assert docx.raw_content.startswith("---")


# ---------------------------------------------------------------------------
# Traversal against the real host installation
# ---------------------------------------------------------------------------


_REAL_SKILLS_ROOT = Path.home() / ".claude" / "skills"
_REAL_SKILLS = sorted(_REAL_SKILLS_ROOT.glob("*/SKILL.md")) if _REAL_SKILLS_ROOT.is_dir() else []


@pytest.mark.skipif(not _REAL_SKILLS, reason="no real Claude Code skill tree on this host")
def test_parses_real_installed_skill_tree(parser: ClaudeSkillsParser) -> None:
    """The parser must find every skill in a genuine installation.

    Complements the upstream corpus by exercising a real machine: many entries
    there are symlinks into plugin directories, which the vendored fixtures do
    not cover.
    """
    assert parser.can_parse(Path.home()) is True

    parsed = parser.parse(Path.home())
    parsed_paths = {s.source_path.resolve() for s in parsed}

    missing = [p for p in _REAL_SKILLS if p.resolve() not in parsed_paths]
    assert not missing, f"{len(missing)} real skills were not discovered, e.g. {missing[:3]}"
