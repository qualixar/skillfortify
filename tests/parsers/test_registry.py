"""Tests for the parser registry.

The ``ParserRegistry`` orchestrates skill discovery across all supported formats.
It maintains a list of registered parsers and tries each one against a target
directory, aggregating all discovered skills into a single list. This allows
``skillfortify scan <path>`` to automatically detect Claude, MCP, and OpenClaw
formats without the user specifying which parser to use.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skillfortify.parsers.base import ParsedSkill
from skillfortify.parsers.registry import ParserRegistry, default_registry


def _sf_skill(skills_dir, name):
    """Return the SKILL.md path for ``<skills_dir>/<name>/``, creating the dir.

    Claude Code skills are directories containing SKILL.md; a bare ``<name>.md``
    in the skills root is not a skill. See
    ``tests/parsers/test_claude_skills_conformance.py``.
    """
    directory = skills_dir / name
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "SKILL.md"




# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def multi_format_dir(tmp_path: Path) -> Path:
    """Create a directory containing skills in all three formats."""
    # Claude skill
    claude_dir = tmp_path / ".claude" / "skills"
    claude_dir.mkdir(parents=True)
    (_sf_skill(claude_dir, "helper")).write_text("---\nname: claude-helper\n---\nContent\n")

    # MCP config
    mcp_config = {
        "mcpServers": {
            "test-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {"PORT": "3000"},
            }
        }
    }
    (tmp_path / "mcp.json").write_text(json.dumps(mcp_config))

    # OpenClaw skill: a directory containing SKILL.md, per the Agent Skills
    # standard. See tests/parsers/test_openclaw_conformance.py.
    claw_skill = tmp_path / ".openclaw" / "skills" / "claw-tool"
    claw_skill.mkdir(parents=True)
    (claw_skill / "SKILL.md").write_text(
        "---\n"
        "name: claw-tool\n"
        'version: "1.0.0"\n'
        "description: A test tool\n"
        "---\n\n"
        "Run it.\n\n"
        "```bash\necho hello\n```\n"
    )

    return tmp_path


# ---------------------------------------------------------------------------
# TestParserRegistry
# ---------------------------------------------------------------------------


class TestParserRegistry:
    """Validate the parser registry and auto-discovery mechanism."""

    def test_default_registry_has_parsers(self) -> None:
        """The default registry ships with all three parsers pre-registered."""
        registry = default_registry()
        assert len(registry.parsers) >= 3

    def test_discovers_all_formats(self, multi_format_dir: Path) -> None:
        """Registry discovers skills across all three formats in a single call."""
        registry = default_registry()
        skills = registry.discover(multi_format_dir)
        formats = {s.format for s in skills}
        assert "claude" in formats
        assert "mcp" in formats
        assert "openclaw" in formats

    def test_empty_dir_returns_empty(self, tmp_path: Path) -> None:
        """An empty directory yields no skills."""
        registry = default_registry()
        skills = registry.discover(tmp_path)
        assert skills == []

    def test_returns_parsed_skill_instances(self, multi_format_dir: Path) -> None:
        """All items returned by discover() are ParsedSkill instances."""
        registry = default_registry()
        skills = registry.discover(multi_format_dir)
        for skill in skills:
            assert isinstance(skill, ParsedSkill)

    def test_register_custom_parser(self, tmp_path: Path) -> None:
        """Custom parsers can be registered and participate in discovery."""
        from skillfortify.parsers.base import SkillParser

        class DummyParser(SkillParser):
            def can_parse(self, path: Path) -> bool:
                return (path / "dummy.txt").exists()

            def parse(self, path: Path) -> list[ParsedSkill]:
                return [
                    ParsedSkill(
                        name="dummy",
                        version="0.0.1",
                        source_path=path / "dummy.txt",
                        format="dummy",
                    )
                ]

        (tmp_path / "dummy.txt").write_text("placeholder")
        registry = ParserRegistry()
        registry.register(DummyParser())
        skills = registry.discover(tmp_path)
        assert len(skills) == 1
        assert skills[0].format == "dummy"

    def test_discover_count_matches_sum_of_individual_parsers(self, multi_format_dir: Path) -> None:
        """Total discovered skills equals the sum from each parser independently."""
        registry = default_registry()
        total = registry.discover(multi_format_dir)
        # We have 1 claude skill + 1 MCP server + 1 claw tool = 3
        assert len(total) == 3

    def test_discover_preserves_skill_data(self, multi_format_dir: Path) -> None:
        """Discovered skills retain their names from individual parsers."""
        registry = default_registry()
        skills = registry.discover(multi_format_dir)
        names = {s.name for s in skills}
        assert "claude-helper" in names
        assert "test-server" in names
        assert "claw-tool" in names
