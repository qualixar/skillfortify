"""Conformance tests for the MCP configuration parser.

Written against the config surfaces MCP clients actually use, verified against
a real machine and vendor documentation on 2026-08-03. The previous
implementation checked six filenames in a single flat directory and therefore
saw exactly one of the seven surfaces present on a working developer machine.

============================================  ========  ==================
File                                          Format    Server key
============================================  ========  ==================
``~/.claude.json``                            JSON      ``mcpServers`` plus
                                                        ``projects.<path>.mcpServers``
``<project>/.mcp.json``                       JSON      ``mcpServers``
``<project>/.vscode/mcp.json``                JSON      ``servers``
``<project>/.cursor/mcp.json``                JSON      ``mcpServers``
``~/.gemini/settings.json``                   JSON      ``mcpServers``
``claude_desktop_config.json``                JSON      ``mcpServers``
``~/.codex/config.toml``                      TOML      ``[mcp_servers.<name>]``
============================================  ========  ==================

The VS Code key is ``servers``, not ``mcpServers`` -- a documented gotcha, and
a good example of why each surface needs its own fixture rather than one
assumed shape.

An MCP server that a scanner cannot see is an MCP server nobody audits, so
coverage of these surfaces is the whole value of this parser.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skillfortify.parsers.mcp_config import McpConfigParser

_SERVER = {"command": "node", "args": ["server.js"], "env": {"API_TOKEN": "x"}}


@pytest.fixture
def parser() -> McpConfigParser:
    return McpConfigParser()


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Project-scoped surfaces
# ---------------------------------------------------------------------------


def test_project_mcp_json_is_discovered(parser: McpConfigParser, tmp_path: Path) -> None:
    """``.mcp.json`` at a repo root is the Claude Code project surface."""
    _write_json(tmp_path / ".mcp.json", {"mcpServers": {"proj-server": _SERVER}})

    assert parser.can_parse(tmp_path) is True
    assert [s.name for s in parser.parse(tmp_path)] == ["proj-server"]


def test_vscode_mcp_json_is_discovered(parser: McpConfigParser, tmp_path: Path) -> None:
    """VS Code stores workspace servers in ``.vscode/mcp.json`` under ``servers``."""
    _write_json(tmp_path / ".vscode" / "mcp.json", {"servers": {"vscode-server": _SERVER}})

    assert parser.can_parse(tmp_path) is True
    assert [s.name for s in parser.parse(tmp_path)] == ["vscode-server"]


def test_cursor_mcp_json_is_discovered(parser: McpConfigParser, tmp_path: Path) -> None:
    """Cursor stores servers in ``.cursor/mcp.json``."""
    _write_json(tmp_path / ".cursor" / "mcp.json", {"mcpServers": {"cursor-server": _SERVER}})

    assert parser.can_parse(tmp_path) is True
    assert [s.name for s in parser.parse(tmp_path)] == ["cursor-server"]


# ---------------------------------------------------------------------------
# User-scoped surfaces
# ---------------------------------------------------------------------------


def test_claude_json_user_config_is_discovered(parser: McpConfigParser, tmp_path: Path) -> None:
    """``~/.claude.json`` is the most widely deployed MCP config file."""
    _write_json(tmp_path / ".claude.json", {"mcpServers": {"user-server": _SERVER}})

    assert parser.can_parse(tmp_path) is True
    assert [s.name for s in parser.parse(tmp_path)] == ["user-server"]


def test_claude_json_project_scoped_servers_are_discovered(
    parser: McpConfigParser, tmp_path: Path
) -> None:
    """``~/.claude.json`` also nests per-project servers under ``projects``.

    These are real, active servers. Missing them means a scan of a developer's
    home directory silently under-reports the attack surface.
    """
    _write_json(
        tmp_path / ".claude.json",
        {
            "mcpServers": {"global-server": _SERVER},
            "projects": {
                "/Users/dev/repo-a": {"mcpServers": {"repo-a-server": _SERVER}},
                "/Users/dev/repo-b": {"mcpServers": {"repo-b-server": _SERVER}},
            },
        },
    )

    found = sorted(s.name for s in parser.parse(tmp_path))
    assert found == ["global-server", "repo-a-server", "repo-b-server"]


def test_gemini_settings_is_discovered(parser: McpConfigParser, tmp_path: Path) -> None:
    """Gemini CLI keeps ``mcpServers`` inside ``~/.gemini/settings.json``."""
    _write_json(tmp_path / ".gemini" / "settings.json", {"mcpServers": {"gemini-server": _SERVER}})

    assert parser.can_parse(tmp_path) is True
    assert [s.name for s in parser.parse(tmp_path)] == ["gemini-server"]


def test_codex_toml_config_is_discovered(parser: McpConfigParser, tmp_path: Path) -> None:
    """Codex declares servers in TOML under ``[mcp_servers.<name>]``."""
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(
        '[mcp_servers.hub]\ncommand = "node"\nargs = ["hub.js"]\n\n'
        '[mcp_servers.node_repl]\ncommand = "node"\nargs = ["repl.js"]\n',
        encoding="utf-8",
    )

    assert parser.can_parse(tmp_path) is True
    assert sorted(s.name for s in parser.parse(tmp_path)) == ["hub", "node_repl"]


# ---------------------------------------------------------------------------
# Aggregation and robustness
# ---------------------------------------------------------------------------


def test_servers_from_multiple_surfaces_are_aggregated(
    parser: McpConfigParser, tmp_path: Path
) -> None:
    """A real machine has several surfaces at once; all must be reported."""
    _write_json(tmp_path / ".mcp.json", {"mcpServers": {"a": _SERVER}})
    _write_json(tmp_path / ".vscode" / "mcp.json", {"servers": {"b": _SERVER}})
    _write_json(tmp_path / ".cursor" / "mcp.json", {"mcpServers": {"c": _SERVER}})

    assert sorted(s.name for s in parser.parse(tmp_path)) == ["a", "b", "c"]


def test_env_vars_are_extracted(parser: McpConfigParser, tmp_path: Path) -> None:
    """Server ``env`` entries are credential surface and must be captured."""
    _write_json(tmp_path / ".mcp.json", {"mcpServers": {"s": _SERVER}})

    (skill,) = parser.parse(tmp_path)
    assert "API_TOKEN" in skill.env_vars_referenced


def test_malformed_config_is_skipped_not_raised(parser: McpConfigParser, tmp_path: Path) -> None:
    """A broken config must not abort a scan of the surrounding tree."""
    (tmp_path / ".mcp.json").write_text("{not valid json", encoding="utf-8")
    _write_json(tmp_path / ".vscode" / "mcp.json", {"servers": {"survivor": _SERVER}})

    assert [s.name for s in parser.parse(tmp_path)] == ["survivor"]


def test_empty_config_is_not_a_match(parser: McpConfigParser, tmp_path: Path) -> None:
    """A config declaring no servers yields nothing."""
    _write_json(tmp_path / ".mcp.json", {"mcpServers": {}})

    assert parser.parse(tmp_path) == []
