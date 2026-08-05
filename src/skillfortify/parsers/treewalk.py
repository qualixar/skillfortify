"""The bounded tree walk shared by every directory-scanning parser.

A scan target is a repository root, not an install root. Skills may sit at the
top level or inside any package below it, and a project may carry several
formats at once, so discovery has to search the tree rather than probe a fixed
relative path.

All parsers traverse through this module. A single implementation keeps the
depth bound, the prune list, and the symlink policy identical for every
format, so what one parser finds another does not miss.

The walk is breadth-first, bounded by ``MAX_SCAN_DEPTH``, and prunes directory
names that do not hold a user's own skills.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Iterator
from pathlib import Path

#: How far below the scan root to descend. Four levels reaches
#: ``packages/<pkg>/<sub>/.claude`` in a typical monorepo without turning a
#: scan of a home directory into a full filesystem crawl.
MAX_SCAN_DEPTH = 4

#: Directory names that never contain a user's own skills. Skipping them is
#: what keeps a scan of a large repository predictable, and it also stops the
#: scanner reporting a dependency's bundled skill as if the user wrote it.
PRUNED_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "target",
        "vendor",
        "venv",
    }
)


def _resolve(path: Path) -> Path | None:
    """Resolve a path, returning None for broken symlinks or permission errors."""
    try:
        return path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def iter_dirs(
    root: Path,
    *,
    max_depth: int = MAX_SCAN_DEPTH,
    include_root: bool = True,
) -> Iterator[Path]:
    """Yield ``root`` and every unpruned directory below it, breadth-first.

    Args:
        root: Directory to start from.
        max_depth: How many levels below ``root`` to descend.
        include_root: Whether to yield ``root`` itself.

    Yields:
        Directories in breadth-first order. A directory whose resolved path
        has already been yielded is skipped, so symlink cycles terminate and
        a tree reachable by two paths is walked once.
    """
    if not root.is_dir():
        return

    root_resolved = _resolve(root)
    if root_resolved is None:
        return

    if include_root:
        yield root

    frontier: deque[tuple[Path, int]] = deque([(root, 0)])
    while frontier:
        current, depth = frontier.popleft()
        if depth >= max_depth:
            continue
        try:
            entries = sorted(current.iterdir())
        except (OSError, PermissionError):
            continue

        for entry in entries:
            if entry.name in PRUNED_DIR_NAMES or not entry.is_dir():
                continue
            yield entry

            # Hidden and symlinked directories are yielded but not entered.
            # Yielding is what matches ``.claude`` and ``.openclaw`` as markers
            # and lets a path like ``.vscode/mcp.json`` resolve from its
            # parent. Not entering is what keeps the walk bounded: a home
            # directory's dotfile trees are large, and a link into a shared or
            # synced folder can expand the search without limit or, if it
            # points at an ancestor, not terminate at all.
            if entry.name.startswith(".") or entry.is_symlink():
                continue
            frontier.append((entry, depth + 1))


def iter_marker_dirs(
    root: Path,
    marker: str,
    *,
    max_depth: int = MAX_SCAN_DEPTH,
) -> Iterator[Path]:
    """Yield every directory named ``marker`` at or below ``root``.

    This is how an install root is located: ``.claude`` and ``.openclaw`` are
    markers, and a repository may hold several of them. ``root`` itself
    counts, so pointing the scanner directly at ``~/.claude`` works.

    Args:
        root: Directory to search from.
        marker: Directory name to match, e.g. ``".claude"``.
        max_depth: How many levels below ``root`` to descend.

    Yields:
        Matching directories in breadth-first order, each once.
    """
    for directory in iter_dirs(root, max_depth=max_depth):
        if directory.name == marker:
            yield directory


def iter_files(
    root: Path,
    relative_paths: Iterable[str],
    *,
    max_depth: int = MAX_SCAN_DEPTH,
) -> Iterator[tuple[Path, Path]]:
    """Yield ``(anchor, file)`` for each ``relative_paths`` match below ``root``.

    Each relative path is re-anchored onto every directory the walk visits,
    which is what makes both ``<root>/.mcp.json`` and
    ``<root>/packages/api/.mcp.json`` discoverable from a single scan.

    The anchor is returned alongside the file because callers need to know
    which project a config belongs to. Two packages may legitimately declare
    servers of the same name, and only the anchor distinguishes them.

    Args:
        root: Directory to search from.
        relative_paths: Paths relative to a candidate directory, e.g.
            ``(".mcp.json", ".vscode/mcp.json")``.
        max_depth: How many levels below ``root`` to descend.

    Yields:
        ``(anchor_directory, file)`` pairs, deduplicated by resolved file
        path, in walk order.
    """
    patterns = tuple(relative_paths)
    seen: set[Path] = set()
    for directory in iter_dirs(root, max_depth=max_depth):
        for relative in patterns:
            candidate = directory / relative
            if not candidate.is_file():
                continue
            resolved = _resolve(candidate)
            if resolved is None or resolved in seen:
                continue
            seen.add(resolved)
            yield directory, candidate
