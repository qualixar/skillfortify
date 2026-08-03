"""Shared test helpers for creating fake IDE home directories.

Each helper creates a minimal but realistic directory structure that
simulates an AI IDE installation. These are used by both
``test_system_scanner.py`` and ``test_scan_system.py``.
"""

from __future__ import annotations

import json
from pathlib import Path


def _sf_skill(skills_dir, name):
    """Return the SKILL.md path for ``<skills_dir>/<name>/``, creating the dir.

    Claude Code skills are directories containing SKILL.md; a bare ``<name>.md``
    in the skills root is not a skill. See
    ``tests/parsers/test_claude_skills_conformance.py``.
    """
    directory = skills_dir / name
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "SKILL.md"




def create_claude_home(home: Path) -> None:
    """Create a fake Claude Code installation under home."""
    claude_dir = home / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    skills_dir = claude_dir / "skills"
    skills_dir.mkdir(exist_ok=True)
    config = claude_dir / "mcp_servers.json"
    config.write_text(json.dumps({"servers": []}))
    skill = _sf_skill(skills_dir, "deploy")
    skill.write_text("# Deploy Skill\nRun: `echo hello`\n")


def create_cursor_home(home: Path) -> None:
    """Create a fake Cursor installation under home."""
    cursor_dir = home / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    config = cursor_dir / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {}}))


def create_windsurf_home(home: Path) -> None:
    """Create a fake Windsurf/Codeium installation under home."""
    windsurf_dir = home / ".codeium" / "windsurf"
    windsurf_dir.mkdir(parents=True, exist_ok=True)
    config = windsurf_dir / "mcp_config.json"
    config.write_text(json.dumps({"servers": []}))


def create_unknown_ide_home(home: Path) -> None:
    """Create a fake unknown AI tool with MCP config."""
    unknown_dir = home / ".mysterytool"
    unknown_dir.mkdir(parents=True, exist_ok=True)
    config = unknown_dir / "mcp.json"
    config.write_text(json.dumps({"tools": []}))


def create_unknown_ide_with_skills(home: Path) -> None:
    """Create a fake unknown AI tool with a skills directory."""
    unknown_dir = home / ".newagent"
    unknown_dir.mkdir(parents=True, exist_ok=True)
    skills = unknown_dir / "skills"
    skills.mkdir(exist_ok=True)
    skill = _sf_skill(skills, "helper")
    skill.write_text("# Helper\nDo stuff.\n")


def create_non_ai_dotdir(home: Path) -> None:
    """Create a regular dot-directory that is NOT an AI tool."""
    git_dir = home / ".git"
    git_dir.mkdir(parents=True, exist_ok=True)
    config = git_dir / "config"
    config.write_text("[core]\n")
