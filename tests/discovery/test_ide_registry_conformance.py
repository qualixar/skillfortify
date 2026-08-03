"""Conformance tests for the IDE profile registry.

The registry hardcodes filesystem paths for every AI tool SkillFortify knows
about. A path that merely *reads* like a real one cannot be disproved from
inside the codebase: the code runs, the tests pass, and the scanner finds
nothing on a real machine. These tests constrain that risk:

1. Structural invariants every profile must satisfy.
2. Retired paths are asserted absent, so they cannot be reintroduced.
3. Exact-path assertions for tools whose layout was verified against vendor
   documentation or a live installation.
4. An empirical check in the only sound direction: config files that exist on
   this host must be known to the registry.

The reverse of (4) -- requiring every declared path to exist here -- is
deliberately *not* asserted. A tool can be installed without ever configuring
MCP, so a missing file proves nothing about a path's correctness. The
reference for correctness is vendor documentation, not one developer's disk.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skillfortify.discovery.ide_registry import _build_profiles

_PROFILES = _build_profiles()

# Retired paths. Asserting their absence stops a plausible-looking string
# from being reintroduced.
_RETIRED_PATHS = {
    ".claude/mcp_servers.json",
}


def test_registry_is_not_empty() -> None:
    assert _PROFILES, "IDE registry is empty"


def test_profiles_have_unique_short_names() -> None:
    """Short names are identifiers; duplicates would silently shadow a tool."""
    short_names = [p.short_name for p in _PROFILES]
    duplicates = {n for n in short_names if short_names.count(n) > 1}
    assert not duplicates, f"duplicate short_name(s): {duplicates}"


def test_profiles_declare_something_discoverable() -> None:
    """Every profile must declare at least one path or dot-directory."""
    empty = [p.name for p in _PROFILES if not (p.config_paths or p.skill_paths or p.dot_dirs)]
    assert not empty, f"profiles with no discoverable surface: {empty}"


def test_declared_paths_are_relative() -> None:
    """Paths are joined onto a scan root, so an absolute path would escape it."""
    absolute = [
        (p.name, path)
        for p in _PROFILES
        for path in list(p.config_paths) + list(p.skill_paths)
        if Path(path).is_absolute()
    ]
    assert not absolute, f"absolute paths in registry: {absolute}"


def test_known_fabricated_paths_are_absent() -> None:
    """Regression guard: retired paths must not reappear."""
    declared = {path for p in _PROFILES for path in list(p.config_paths) + list(p.skill_paths)}
    reintroduced = declared & _RETIRED_PATHS
    assert not reintroduced, f"retired path(s) reintroduced: {reintroduced}"


def test_claude_code_profile_matches_reality() -> None:
    """Claude Code's real config surfaces, verified against a live install."""
    claude = next(p for p in _PROFILES if p.short_name == "claude")
    assert ".claude.json" in claude.config_paths
    assert ".mcp.json" in claude.config_paths
    assert ".claude/skills" in claude.skill_paths


# ---------------------------------------------------------------------------
# Documented paths, verified against vendor documentation
# ---------------------------------------------------------------------------

# Exact paths confirmed against vendor documentation or a live installation.
# Only verified tools belong here; an unverified entry would defeat the purpose
# of the check.
_VERIFIED_PATHS = {
    "claude": [
        ".claude.json",
        ".mcp.json",
        "Library/Application Support/Claude/claude_desktop_config.json",
    ],
    "codex": [".codex/config.toml"],
    "cursor": [".cursor/mcp.json"],
    "gemini": [".gemini/settings.json"],
    "openclaw": [".openclaw/skills"],
    "windsurf": [".codeium/windsurf/mcp_config.json"],
}


@pytest.mark.parametrize("short_name,expected", sorted(_VERIFIED_PATHS.items()))
def test_verified_paths_are_declared(short_name: str, expected: list[str]) -> None:
    """Each verified path must appear in its profile.

    Note what this does *not* assert: that the path exists on this machine. A
    tool can be installed without ever configuring MCP, so absence proves
    nothing. Presence in the registry is what matters, and the reference for
    correctness is vendor documentation, not this developer's filesystem.
    """
    profile = next((p for p in _PROFILES if p.short_name == short_name), None)
    assert profile is not None, f"no profile registered for {short_name!r}"

    declared = set(profile.config_paths) | set(profile.skill_paths)
    missing = [path for path in expected if path not in declared]
    assert not missing, f"{profile.name} is missing verified path(s): {missing}"


def test_paths_found_on_this_host_are_declared() -> None:
    """Any real config file on this machine should be known to the registry.

    This is the empirical direction that *is* sound: we look at what exists,
    then check the registry knows about it. The reverse -- demanding that every
    declared path exist here -- would fail for every tool the user has
    installed but not configured.
    """
    home = Path.home()
    declared = {path for p in _PROFILES for path in list(p.config_paths) + list(p.skill_paths)}

    known_real_configs = [
        ".claude.json",
        ".gemini/settings.json",
        ".codex/config.toml",
        "Library/Application Support/Claude/claude_desktop_config.json",
    ]
    present = [c for c in known_real_configs if (home / c).exists()]
    if not present:
        pytest.skip("none of the reference configs exist on this host")

    undeclared = [c for c in present if c not in declared]
    assert not undeclared, (
        f"config files exist on this host but are not in the registry: {undeclared}"
    )
