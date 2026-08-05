"""Every format must be discoverable at depth, not only at the scan root.

A user points the scanner at a repository root, not at each install root
inside it, so a skill held in a package below that root has to be found by the
same single scan. These tests hold all three formats to one contract: for each
format, one specimen at the root and one nested, both required.
"""

import json

import pytest

from skillfortify.parsers.registry import default_registry

SKILL_MD = """---
name: {name}
description: A demonstration skill.
---

Reads a file and prints its contents.
"""

MCP_CONFIG = {
    "mcpServers": {
        "{name}": {"command": "node", "args": ["server.js"]},
    }
}


def _write_skill(directory, name):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "SKILL.md").write_text(SKILL_MD.format(name=name))


def _write_mcp_config(path, name):
    path.parent.mkdir(parents=True, exist_ok=True)
    config = {"mcpServers": {name: {"command": "node", "args": ["server.js"]}}}
    path.write_text(json.dumps(config))


@pytest.fixture
def monorepo(tmp_path):
    """A repository with one install root at the top and one in a package."""
    _write_skill(tmp_path / ".claude/skills/claude-root", "claude-root")
    _write_skill(tmp_path / "packages/web/.claude/skills/claude-nested", "claude-nested")
    _write_skill(tmp_path / ".openclaw/skills/openclaw-root", "openclaw-root")
    _write_skill(
        tmp_path / "packages/web/.openclaw/skills/openclaw-nested", "openclaw-nested"
    )
    _write_mcp_config(tmp_path / ".mcp.json", "mcp-root")
    _write_mcp_config(tmp_path / "packages/api/.mcp.json", "mcp-nested")
    return tmp_path


def _discovered_names(root):
    return {skill.name for skill in default_registry().discover(root)}


@pytest.mark.parametrize(
    "name",
    [
        "claude-root",
        "claude-nested",
        "openclaw-root",
        "openclaw-nested",
        "mcp-root",
        "mcp-nested",
    ],
)
def test_every_format_is_found_at_root_and_at_depth(monorepo, name):
    """No format may be discoverable only when it sits at the scan root."""
    assert name in _discovered_names(monorepo)


def test_discovery_finds_exactly_the_planted_skills(monorepo):
    """A count check catches duplicate yields that the membership tests miss."""
    assert len(_discovered_names(monorepo)) == 6


def test_pruned_directories_are_not_descended(tmp_path):
    """Dependency trees are skipped: a vendored skill is not the user's skill."""
    _write_skill(tmp_path / ".claude/skills/real", "real")
    _write_skill(tmp_path / "node_modules/pkg/.claude/skills/vendored", "vendored")
    _write_skill(tmp_path / "node_modules/pkg/.openclaw/skills/vendored-oc", "vendored-oc")
    _write_mcp_config(tmp_path / "node_modules/pkg/.mcp.json", "vendored-mcp")

    names = _discovered_names(tmp_path)

    assert "real" in names
    assert not {"vendored", "vendored-oc", "vendored-mcp"} & names


def test_symlinked_directories_do_not_cause_infinite_recursion(tmp_path):
    """A directory symlink pointing at an ancestor must not hang the walk."""
    _write_skill(tmp_path / ".claude/skills/real", "real")
    _write_skill(tmp_path / ".openclaw/skills/real-oc", "real-oc")
    loop = tmp_path / "packages"
    loop.mkdir(parents=True, exist_ok=True)
    try:
        (loop / "loop").symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks unavailable on this platform")

    names = _discovered_names(tmp_path)

    assert {"real", "real-oc"} <= names


def test_same_server_name_in_two_packages_is_not_collapsed(tmp_path):
    """Two packages may each declare a ``github`` server; both must be scanned.

    Server names are unique only within a project, so deduplication is scoped
    to the project directory. A key of the bare name would drop every package
    after the first, and the dropped one may be the one carrying the finding.
    """
    for pkg, command in (("api", "node"), ("web", "python")):
        config = {"mcpServers": {"github": {"command": command, "args": ["s.js"]}}}
        target = tmp_path / "packages" / pkg / ".mcp.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(config))

    from skillfortify.parsers.mcp_config import McpConfigParser

    skills = McpConfigParser().parse(tmp_path)

    assert len(skills) == 2
    assert {s.source_path.parent.name for s in skills} == {"api", "web"}


def test_one_server_declared_in_two_client_configs_is_reported_once(tmp_path):
    """One project declaring the same server to two clients is still one server."""
    config = {"mcpServers": {"github": {"command": "node", "args": ["s.js"]}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode/mcp.json").write_text(json.dumps(config))

    from skillfortify.parsers.mcp_config import McpConfigParser

    assert len(McpConfigParser().parse(tmp_path)) == 1


def test_same_skill_reachable_by_two_paths_is_reported_once(tmp_path):
    """Deduplication is by resolved path, so a symlinked root is not double counted."""
    _write_skill(tmp_path / "repo/.openclaw/skills/only-once", "only-once")
    try:
        (tmp_path / "mirror").symlink_to(tmp_path / "repo", target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks unavailable on this platform")

    skills = [s for s in default_registry().discover(tmp_path) if s.name == "only-once"]

    assert len(skills) == 1
