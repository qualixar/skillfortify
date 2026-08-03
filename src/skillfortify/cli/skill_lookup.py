"""Locate the project root that owns a single skill file.

``verify`` and ``trust`` accept one skill *file*, but parsers operate on a
project *directory*. This module bridges the two.

Claude Code lets a ``<skill-name>`` entry be a symlink, and plugin-managed
skills routinely are: ``~/.claude/skills/foo`` may point at
``~/.claude/plugins/local/some-plugin/skills/foo``. Resolving the path first
would move the search into the plugin's location, where no ancestor is a
project root.

The path is therefore walked *as given*, anchored on the nearest ``.claude``
ancestor, whose parent is the project root by definition.
"""

from __future__ import annotations

from pathlib import Path

from skillfortify.parsers.registry import default_registry

# How far to walk up when no .claude ancestor is present (plugin trees,
# bare MCP configs, skills reached through an unusual mount).
_MAX_WALK_UP = 8

_CLAUDE_DIR = ".claude"


def find_project_root(skill_path: Path) -> Path | None:
    """Return the directory a parser should be pointed at for ``skill_path``.

    Args:
        skill_path: Path to a single skill file, as supplied by the user.
            It is deliberately *not* resolved first; see module docstring.

    Returns:
        The owning project root, or None if no ancestor yields any skill.
    """
    candidates: list[Path] = []

    # Preferred anchor: the parent of the nearest `.claude` ancestor.
    for ancestor in skill_path.parents:
        if ancestor.name == _CLAUDE_DIR:
            candidates.append(ancestor.parent)
            break

    # Fall back to walking up from the file, both as given and resolved, so a
    # symlinked skill is still found via its real location if the anchor missed.
    for start in _distinct((skill_path.parent, _resolved_parent(skill_path))):
        current = start
        for _ in range(_MAX_WALK_UP):
            candidates.append(current)
            if current.parent == current:
                break
            current = current.parent

    registry = default_registry()
    for candidate in _distinct(candidates):
        if registry.discover(candidate):
            return candidate
    return None


def _resolved_parent(path: Path) -> Path:
    """Parent of ``path`` with symlinks resolved, falling back on error."""
    try:
        return path.resolve().parent
    except (OSError, RuntimeError):
        return path.parent


def _distinct(paths: object) -> list[Path]:
    """De-duplicate paths while preserving order."""
    seen: set[Path] = set()
    ordered: list[Path] = []
    for path in paths:  # type: ignore[union-attr]
        if path not in seen:
            seen.add(path)
            ordered.append(path)
    return ordered
