"""Conformance tests for the OpenClaw skills parser.

Written against the real OpenClaw skill format documented at
https://docs.openclaw.ai/tools/skills and
https://github.com/openclaw/clawhub/blob/main/docs/skill-format.md,
verified 2026-08-03.

OpenClaw skills use the same `Agent Skills <https://agentskills.io>`_ standard
Claude Code uses: a skill is a *directory* containing ``SKILL.md``, whose YAML
frontmatter carries ``name``, ``description``, ``version``, and OpenClaw
runtime requirements under ``metadata.openclaw``:

.. code-block:: yaml

    ---
    name: web-scraper
    description: Scrapes pages and extracts structured data
    version: 1.3.0
    metadata:
      openclaw:
        requires:
          env: [SCRAPER_API_KEY]
          bins: [curl]
    ---

Load locations are ``~/.openclaw/skills/``, ``<workspace>/skills/``, and
``.openclaw/skills/`` at a repo root, with discovery recursing up to six
levels below each root.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skillfortify.parsers.openclaw import OpenClawParser


@pytest.fixture
def parser() -> OpenClawParser:
    return OpenClawParser()


def _write_skill(directory: Path, name: str, frontmatter: str = "", body: str = "") -> Path:
    """Write ``<directory>/<name>/SKILL.md`` and return its path."""
    skill_dir = directory / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_file = skill_dir / "SKILL.md"
    extra = f"{frontmatter}\n" if frontmatter else ""
    skill_file.write_text(
        f"---\nname: {name}\ndescription: Test skill {name}\n{extra}---\n\n{body}",
        encoding="utf-8",
    )
    return skill_file


# ---------------------------------------------------------------------------
# Real load locations
# ---------------------------------------------------------------------------


def test_dot_openclaw_skills_directory_is_discovered(
    parser: OpenClawParser, tmp_path: Path
) -> None:
    """Project skills live at ``.openclaw/skills/<name>/SKILL.md``."""
    _write_skill(tmp_path / ".openclaw" / "skills", "web-scraper")

    assert parser.can_parse(tmp_path) is True
    assert [s.name for s in parser.parse(tmp_path)] == ["web-scraper"]


def test_workspace_skills_directory_is_discovered(parser: OpenClawParser, tmp_path: Path) -> None:
    """A bare ``<workspace>/skills/`` directory is a documented load location."""
    _write_skill(tmp_path / "skills", "workspace-skill")

    assert parser.can_parse(tmp_path) is True
    assert [s.name for s in parser.parse(tmp_path)] == ["workspace-skill"]


def test_nested_skills_are_discovered(parser: OpenClawParser, tmp_path: Path) -> None:
    """OpenClaw finds SKILL.md anywhere under a root, for organisation folders."""
    _write_skill(tmp_path / ".openclaw" / "skills" / "research", "deep-dive")

    assert [s.name for s in parser.parse(tmp_path)] == ["deep-dive"]


def test_format_identifier_is_openclaw(parser: OpenClawParser, tmp_path: Path) -> None:
    """Parsed skills must carry the openclaw format tag."""
    _write_skill(tmp_path / ".openclaw" / "skills", "tagged")

    (skill,) = parser.parse(tmp_path)
    assert skill.format == "openclaw"


# ---------------------------------------------------------------------------
# Negative cases -- non-OpenClaw layouts must not be accepted
# ---------------------------------------------------------------------------


def test_claw_yaml_layout_is_not_accepted(parser: OpenClawParser, tmp_path: Path) -> None:
    """``.claw/*.yaml`` is not an OpenClaw layout and must not be accepted."""
    claw_dir = tmp_path / ".claw"
    claw_dir.mkdir()
    (claw_dir / "web-scraper.yaml").write_text(
        "name: web-scraper\nversion: 1.0.0\ncommands: []\n", encoding="utf-8"
    )

    assert parser.can_parse(tmp_path) is False
    assert parser.parse(tmp_path) == []


def test_skill_directory_without_skill_md_is_ignored(
    parser: OpenClawParser, tmp_path: Path
) -> None:
    """A directory with no SKILL.md is not a skill."""
    (tmp_path / ".openclaw" / "skills" / "empty").mkdir(parents=True)

    assert parser.can_parse(tmp_path) is False


# ---------------------------------------------------------------------------
# Frontmatter and security-relevant extraction
# ---------------------------------------------------------------------------


def test_version_is_read_from_frontmatter(parser: OpenClawParser, tmp_path: Path) -> None:
    """``version`` is a documented registry-publishing field."""
    _write_skill(tmp_path / ".openclaw" / "skills", "versioned", frontmatter="version: 1.3.0")

    (skill,) = parser.parse(tmp_path)
    assert skill.version == "1.3.0"


def test_required_env_vars_are_extracted_from_metadata(
    parser: OpenClawParser, tmp_path: Path
) -> None:
    """``metadata.openclaw.requires.env`` declares credentials the skill reads."""
    _write_skill(
        tmp_path / ".openclaw" / "skills",
        "needs-creds",
        frontmatter=(
            "metadata:\n  openclaw:\n    requires:\n      env: [SCRAPER_API_KEY, PROXY_TOKEN]\n"
        ),
    )

    (skill,) = parser.parse(tmp_path)
    assert "SCRAPER_API_KEY" in skill.env_vars_referenced
    assert "PROXY_TOKEN" in skill.env_vars_referenced


def test_required_bins_are_recorded_as_dependencies(parser: OpenClawParser, tmp_path: Path) -> None:
    """``requires.bins`` is an execution-surface dependency."""
    _write_skill(
        tmp_path / ".openclaw" / "skills",
        "needs-bins",
        frontmatter=("metadata:\n  openclaw:\n    requires:\n      bins: [curl, jq]\n"),
    )

    (skill,) = parser.parse(tmp_path)
    assert "curl" in skill.dependencies
    assert "jq" in skill.dependencies


def test_urls_and_shell_commands_are_extracted_from_body(
    parser: OpenClawParser, tmp_path: Path
) -> None:
    """Exfiltration endpoints and shell commands are the core threat signals."""
    _write_skill(
        tmp_path / ".openclaw" / "skills",
        "scraper",
        body=(
            "Fetch data from https://target-site.com/api.\n\n"
            "```bash\n"
            "curl -H 'Authorization: Bearer $SCRAPER_API_KEY' https://target-site.com\n"
            "```\n"
        ),
    )

    (skill,) = parser.parse(tmp_path)
    assert any("target-site.com" in u for u in skill.urls)
    assert any("curl" in c for c in skill.shell_commands)
    assert "SCRAPER_API_KEY" in skill.env_vars_referenced


def test_name_defaults_to_directory_name(parser: OpenClawParser, tmp_path: Path) -> None:
    """The directory name and frontmatter name are kept aligned upstream."""
    skill_dir = tmp_path / ".openclaw" / "skills" / "inferred"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\ndescription: no name field\n---\n\nBody.\n", encoding="utf-8"
    )

    (skill,) = parser.parse(tmp_path)
    assert skill.name == "inferred"


def test_malformed_frontmatter_does_not_crash(parser: OpenClawParser, tmp_path: Path) -> None:
    """A broken skill must be skipped, not raise."""
    skill_dir = tmp_path / ".openclaw" / "skills" / "broken"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: [unclosed\n---\n\nBody.\n", encoding="utf-8")

    assert [s.name for s in parser.parse(tmp_path)] == ["broken"]


# ---------------------------------------------------------------------------
# Conformance against upstream-authored artifacts
# ---------------------------------------------------------------------------

# Skills copied verbatim from the official OpenClaw registry. See
# tests/fixtures/openclaw/PROVENANCE.md for source commit and hashes. These are
# the gate for issue #8: artifacts this project did not write.
_FIXTURE_ROOT = Path(__file__).parent.parent / "fixtures" / "openclaw"
_FIXTURE_SKILLS = sorted((_FIXTURE_ROOT / "skills").glob("*/SKILL.md"))


def test_upstream_fixtures_are_present() -> None:
    """The vendored upstream corpus must exist; silently skipping it hides drift."""
    assert _FIXTURE_SKILLS, f"no upstream fixtures under {_FIXTURE_ROOT}"
    assert (_FIXTURE_ROOT / "PROVENANCE.md").is_file()


def test_parses_every_upstream_skill(parser: OpenClawParser) -> None:
    """Every skill published by the upstream registry must be discovered."""
    assert parser.can_parse(_FIXTURE_ROOT) is True

    parsed = parser.parse(_FIXTURE_ROOT)
    parsed_paths = {s.source_path.resolve() for s in parsed}
    missing = [p for p in _FIXTURE_SKILLS if p.resolve() not in parsed_paths]
    assert not missing, f"{len(missing)} upstream skills not discovered: {missing}"


def test_upstream_skills_yield_usable_metadata(parser: OpenClawParser) -> None:
    """Real skills must produce the fields downstream analysis depends on.

    Upstream skills commonly declare only ``name`` and ``description`` -- no
    ``version`` and no ``metadata.openclaw`` block -- so the parser must degrade
    to sensible defaults rather than dropping the skill.
    """
    skills = {s.name: s for s in parser.parse(_FIXTURE_ROOT)}

    assert "openclaw-brand" in skills
    brand = skills["openclaw-brand"]
    assert brand.format == "openclaw"
    assert brand.description.strip()
    assert brand.version == "unknown"  # upstream omits `version`
    assert brand.raw_content.startswith("---")


@pytest.mark.skipif(
    not (Path.home() / ".openclaw" / "skills").is_dir(),
    reason="no ~/.openclaw/skills tree on this host",
)
def test_traverses_host_load_path_including_symlinks(parser: OpenClawParser) -> None:
    """Load-path traversal check against whatever is on this machine.

    This complements the upstream corpus: it exercises the real
    ``~/.openclaw/skills`` load path, where entries are frequently symlinks
    into another agent's skill directory. It asserts traversal and symlink
    handling, *not* format conformance -- the host tree is not necessarily
    upstream-authored.
    """
    host_skills = sorted((Path.home() / ".openclaw" / "skills").glob("*/SKILL.md"))
    if not host_skills:
        pytest.skip("host load path present but empty")

    parsed_paths = {s.source_path.resolve() for s in parser.parse(Path.home())}
    missing = [p for p in host_skills if p.resolve() not in parsed_paths]
    assert not missing, f"{len(missing)} skills on the host load path were not discovered"
