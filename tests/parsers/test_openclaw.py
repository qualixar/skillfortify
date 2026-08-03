"""Tests for the OpenClaw skills parser.

OpenClaw skills use the Agent Skills open standard: a skill is a directory
containing ``SKILL.md`` with YAML frontmatter and markdown instructions, loaded
from ``~/.openclaw/skills/``, ``<workspace>/skills/``, or ``.openclaw/skills/``.

This module covers per-file parsing behaviour -- frontmatter handling, metadata
extraction, and malformed input. Layout and discovery conformance against the
published specification lives in ``test_openclaw_conformance.py``.

Fixtures follow the published layout so that they test the format OpenClaw
actually ships rather than an assumption made inside this project.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skillfortify.parsers.base import ParsedSkill
from skillfortify.parsers.openclaw import OpenClawParser

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def parser() -> OpenClawParser:
    return OpenClawParser()


@pytest.fixture
def openclaw_skill_dir(tmp_path: Path) -> Path:
    """Create ``.openclaw/skills/web-scraper/SKILL.md`` with a realistic skill."""
    skill_dir = tmp_path / ".openclaw" / "skills" / "web-scraper"
    skill_dir.mkdir(parents=True)

    (skill_dir / "SKILL.md").write_text(
        """\
---
name: web-scraper
version: "1.3.0"
description: Scrapes web pages and extracts structured data
metadata:
  openclaw:
    requires:
      env: [SCRAPER_API_KEY]
      bins: [curl]
---

Use this skill to scrape data from https://target-site.com/api.
Also connects to https://proxy.internal.net for rate limiting.

```bash
curl -H 'Authorization: Bearer $SCRAPER_API_KEY' https://target-site.com
python export.py --output /tmp/data.json
```
""",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def workspace_skill_dir(tmp_path: Path) -> Path:
    """Create a workspace-level ``skills/code-reviewer/SKILL.md``."""
    skill_dir = tmp_path / "skills" / "code-reviewer"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: code-reviewer\nversion: 0.2.0\ndescription: Reviews code\n---\n\nReview it.\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def empty_skills_dir(tmp_path: Path) -> Path:
    """Create an empty ``.openclaw/skills/`` directory."""
    (tmp_path / ".openclaw" / "skills").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def malformed_skill_dir(tmp_path: Path) -> Path:
    """Create a skill whose frontmatter is not valid YAML."""
    skill_dir = tmp_path / ".openclaw" / "skills" / "broken"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: [invalid yaml\n  missing: {bracket\n---\n\nBody.\n", encoding="utf-8"
    )
    return tmp_path


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class TestOpenClawDetection:
    def test_can_parse_project_skills(
        self, parser: OpenClawParser, openclaw_skill_dir: Path
    ) -> None:
        """A ``.openclaw/skills/`` tree containing a SKILL.md is detected."""
        assert parser.can_parse(openclaw_skill_dir) is True

    def test_can_parse_workspace_skills(
        self, parser: OpenClawParser, workspace_skill_dir: Path
    ) -> None:
        """A ``<workspace>/skills/`` tree is detected."""
        assert parser.can_parse(workspace_skill_dir) is True

    def test_cannot_parse_empty_skills_dir(
        self, parser: OpenClawParser, empty_skills_dir: Path
    ) -> None:
        """An empty skills directory is not parseable."""
        assert parser.can_parse(empty_skills_dir) is False

    def test_cannot_parse_unrelated_directory(self, parser: OpenClawParser, tmp_path: Path) -> None:
        """A directory with no skills directory is not parseable."""
        (tmp_path / "src").mkdir()
        assert parser.can_parse(tmp_path) is False


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class TestOpenClawParser:
    def test_parses_skill_name(self, parser: OpenClawParser, openclaw_skill_dir: Path) -> None:
        (skill,) = parser.parse(openclaw_skill_dir)
        assert skill.name == "web-scraper"

    def test_parses_version(self, parser: OpenClawParser, openclaw_skill_dir: Path) -> None:
        (skill,) = parser.parse(openclaw_skill_dir)
        assert skill.version == "1.3.0"

    def test_extracts_description(self, parser: OpenClawParser, openclaw_skill_dir: Path) -> None:
        (skill,) = parser.parse(openclaw_skill_dir)
        assert "Scrapes web pages" in skill.description

    def test_extracts_instructions(self, parser: OpenClawParser, openclaw_skill_dir: Path) -> None:
        """Instructions are the markdown body, with frontmatter stripped."""
        (skill,) = parser.parse(openclaw_skill_dir)
        assert "scrape data" in skill.instructions
        assert "version:" not in skill.instructions

    def test_extracts_urls(self, parser: OpenClawParser, openclaw_skill_dir: Path) -> None:
        (skill,) = parser.parse(openclaw_skill_dir)
        joined = " ".join(skill.urls)
        assert "target-site.com" in joined
        assert "proxy.internal.net" in joined

    def test_extracts_env_vars(self, parser: OpenClawParser, openclaw_skill_dir: Path) -> None:
        """Declared and referenced env vars are merged."""
        (skill,) = parser.parse(openclaw_skill_dir)
        assert "SCRAPER_API_KEY" in skill.env_vars_referenced

    def test_extracts_shell_commands(
        self, parser: OpenClawParser, openclaw_skill_dir: Path
    ) -> None:
        (skill,) = parser.parse(openclaw_skill_dir)
        assert any("curl" in c for c in skill.shell_commands)
        assert any("export.py" in c for c in skill.shell_commands)

    def test_extracts_required_bins_as_dependencies(
        self, parser: OpenClawParser, openclaw_skill_dir: Path
    ) -> None:
        (skill,) = parser.parse(openclaw_skill_dir)
        assert "curl" in skill.dependencies

    def test_format_is_correct(self, parser: OpenClawParser, openclaw_skill_dir: Path) -> None:
        (skill,) = parser.parse(openclaw_skill_dir)
        assert skill.format == "openclaw"

    def test_source_path_is_set(self, parser: OpenClawParser, openclaw_skill_dir: Path) -> None:
        (skill,) = parser.parse(openclaw_skill_dir)
        assert skill.source_path.name == "SKILL.md"
        assert skill.source_path.parent.name == "web-scraper"

    def test_raw_content_preserved(self, parser: OpenClawParser, openclaw_skill_dir: Path) -> None:
        """raw_content keeps the whole file, frontmatter included."""
        (skill,) = parser.parse(openclaw_skill_dir)
        assert skill.raw_content.startswith("---")
        assert "version:" in skill.raw_content

    def test_returns_parsed_skill_instances(
        self, parser: OpenClawParser, openclaw_skill_dir: Path
    ) -> None:
        skills = parser.parse(openclaw_skill_dir)
        assert all(isinstance(s, ParsedSkill) for s in skills)


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


class TestOpenClawRobustness:
    def test_handles_empty_dir(self, parser: OpenClawParser, empty_skills_dir: Path) -> None:
        assert parser.parse(empty_skills_dir) == []

    def test_handles_malformed_frontmatter(
        self, parser: OpenClawParser, malformed_skill_dir: Path
    ) -> None:
        """A broken skill is still surfaced, falling back to the directory name."""
        skills = parser.parse(malformed_skill_dir)
        assert [s.name for s in skills] == ["broken"]

    def test_handles_nonexistent_path(self, parser: OpenClawParser, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"
        assert parser.can_parse(missing) is False
        assert parser.parse(missing) == []
