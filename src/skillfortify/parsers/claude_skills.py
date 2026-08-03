"""Parser for Claude Code skills (``<skill-name>/SKILL.md``).

A Claude Code skill is a *directory* containing a ``SKILL.md`` file: markdown
instructions preceded by YAML frontmatter delimited by ``---`` lines. It is
never a bare Markdown file sitting directly in ``.claude/skills/``.

Skills load from four places (verified against
https://code.claude.com/docs/en/skills on 2026-08-03):

===========  ====================================================
Level        Path
===========  ====================================================
Personal     ``~/.claude/skills/<skill-name>/SKILL.md``
Project      ``.claude/skills/<skill-name>/SKILL.md``
Plugin       ``<plugin>/skills/<skill-name>/SKILL.md``
Legacy       ``.claude/commands/<name>.md``
===========  ====================================================

Nested ``.claude/skills/`` directories below the scan root also load, so a
monorepo package can ship skills scoped to that package. The format is the
`Agent Skills <https://agentskills.io>`_ open standard, shared with other
agent runtimes.

The parser extracts security-relevant signals from both the frontmatter and
the Markdown body:

- **URLs** -- Potential data exfiltration endpoints (DY-Skill attack surface:
  EXECUTE phase, DATA_EXFILTRATION class).
- **Environment variables** -- Credential exposure risk. Patterns matching
  SECRET, KEY, TOKEN, PASSWORD, CREDENTIAL are flagged as high-risk.
- **Shell commands** -- Code execution attack surface. Extracted from bash
  code blocks and inline backtick commands.
- **Code blocks** -- Raw code for deeper static analysis passes.

- **Declared tool grants** -- ``allowed-tools`` pre-approves tools for the
  invoking turn with no permission prompt, and ``disallowed-tools`` removes
  them; both are recorded as declared capabilities (input to the POLA check).

Frontmatter Parsing
-------------------
The content between the ``---`` markers is parsed as YAML. Upstream makes
``name`` optional -- it defaults to the skill's *directory* name, not the
filename -- so that default is reproduced here.

References:
    Claude Code skills reference, https://code.claude.com/docs/en/skills.
    Layout verified against a live installation; see
    ``tests/parsers/test_claude_skills_conformance.py``, which asserts against
    the real skill tree on the host rather than a fixture authored here.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import yaml

from skillfortify.parsers.base import ParsedSkill, SkillParser

# ---------------------------------------------------------------------------
# Upstream layout constants (https://code.claude.com/docs/en/skills)
# ---------------------------------------------------------------------------

# A skill is a directory containing this file. It is never a bare .md file.
_SKILL_FILENAME = "SKILL.md"

_CLAUDE_DIR = ".claude"
_SKILLS_DIR = "skills"
_PLUGINS_DIR = "plugins"

# Legacy custom commands were merged into skills upstream and still load.
_COMMANDS_DIR = "commands"

# Default bound on how deep a nested .claude/ may sit below the scan root.
# Cost is highly non-linear on a large tree: measured against a real home
# directory, depth 4 finds 197 skills in 1.6s while depth 8 finds 315 in 54s.
# Callers that need exhaustive coverage can raise it via the constructor.
_MAX_SCAN_DEPTH = 4

# Directories that never contain skills; pruned to keep scans bounded.
_PRUNED_DIR_NAMES = frozenset(
    {
        "node_modules",
        "__pycache__",
        "venv",
        "site-packages",
        "dist",
        "build",
        "target",
        "vendor",
    }
)

# ---------------------------------------------------------------------------
# Regex patterns for security-relevant content extraction
# ---------------------------------------------------------------------------

# Match URLs: http:// or https:// followed by non-whitespace characters.
_URL_PATTERN = re.compile(r"https?://[^\s\"'`)\]>]+")

# Match environment variable references. Captures identifiers that:
# - Are at least 2 characters long
# - Contain at least one underscore or are fully uppercase
# - Common patterns: DEPLOY_TOKEN, AWS_SECRET_ACCESS_KEY, API_KEY
# We avoid matching generic words by requiring an underscore or
# the pattern to appear after os.environ, $, or export.
_ENV_VAR_PATTERN = re.compile(
    r"""(?:"""
    r"""\$\{?([A-Z][A-Z0-9_]{1,})\}?"""  # $VAR or ${VAR}
    r"""|os\.environ\[["']([A-Z][A-Z0-9_]{1,})["']\]"""  # os.environ["VAR"]
    r"""|os\.getenv\(["']([A-Z][A-Z0-9_]{1,})["']\)"""  # os.getenv("VAR")
    r"""|export\s+([A-Z][A-Z0-9_]{1,})"""  # export VAR
    # Standalone ALL_CAPS *with* an underscore. The underscore is required:
    # without it, any capitalised word in prose ("NOTE", "TODO", "MIT") reads
    # as an environment variable and infers an environment:READ capability the
    # skill never asked for, which then surfaces as a least-privilege
    # violation. Single-word variables still match through the sigil
    # alternatives above ($PATH, ${HOME}, os.environ["PATH"]).
    r"""|(?:^|[\s=:`])([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)(?=[=\s"'`])"""
    r""")""",
    re.MULTILINE,
)

# Sensitive env var name fragments that warrant heightened scrutiny.
_SENSITIVE_FRAGMENTS = {"SECRET", "KEY", "TOKEN", "PASSWORD", "CREDENTIAL"}

# Match fenced code blocks: ```lang\n...\n```
_CODE_BLOCK_PATTERN = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)

# Match YAML frontmatter: ---\n...\n---
_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def _extract_env_vars(text: str) -> list[str]:
    """Extract unique environment variable names from text.

    Searches for multiple patterns: $VAR, ${VAR}, os.environ["VAR"],
    os.getenv("VAR"), export VAR, and standalone ALL_CAPS identifiers
    containing at least one underscore.

    Returns:
        Deduplicated list of env var names found in the text.
    """
    found: set[str] = set()
    for match in _ENV_VAR_PATTERN.finditer(text):
        # Each group corresponds to a different capture pattern.
        for group in match.groups():
            if group:
                found.add(group)
    return sorted(found)


def _extract_urls(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from text."""
    return _URL_PATTERN.findall(text)


def _extract_code_blocks(text: str) -> list[str]:
    """Extract the content of all fenced code blocks."""
    return [match.group(2) for match in _CODE_BLOCK_PATTERN.finditer(text)]


def _safe_resolve(path: Path) -> Path | None:
    """Resolve a path, returning None for broken symlinks or permission errors."""
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved


def _iter_claude_dirs(root: Path, max_depth: int = _MAX_SCAN_DEPTH) -> Iterator[Path]:
    """Yield every ``.claude`` directory at or below ``root``.

    Uses a breadth-first walk bounded by ``max_depth`` and prunes
    directories that never contain skills (VCS metadata, dependency trees,
    virtualenvs). Scanning a home directory or a large monorepo therefore
    stays predictable instead of descending the entire filesystem.
    """
    frontier = [(root, 0)]
    while frontier:
        current, depth = frontier.pop(0)
        try:
            entries = sorted(current.iterdir())
        except (OSError, PermissionError):
            continue

        for entry in entries:
            if not entry.is_dir() or entry.is_symlink():
                continue
            if entry.name == _CLAUDE_DIR:
                yield entry
                continue
            if depth >= max_depth or entry.name in _PRUNED_DIR_NAMES:
                continue
            if entry.name.startswith("."):
                continue
            frontier.append((entry, depth + 1))


def _iter_dirs(root: Path, pattern: str, max_depth: int = _MAX_SCAN_DEPTH) -> Iterator[Path]:
    """Yield existing directories matching ``pattern`` under any ``.claude`` root.

    ``pattern`` is expressed relative to the scan root and always begins with
    ``.claude``; it is re-anchored onto every ``.claude`` directory found at or
    below ``root``. This is what makes both ``<root>/.claude/skills`` and
    ``<root>/packages/web/.claude/skills`` discoverable.
    """
    relative = pattern.split("/", 1)[1] if "/" in pattern else ""
    for claude_dir in _iter_claude_dirs(root, max_depth):
        if not relative:
            yield claude_dir
            continue
        if "*" in relative:
            for match in sorted(claude_dir.glob(relative)):
                if match.is_dir():
                    yield match
        else:
            candidate = claude_dir / relative
            if candidate.is_dir():
                yield candidate


def _declared_tool_capabilities(fm_data: dict[str, object]) -> list[str]:
    """Extract ``allowed-tools`` / ``disallowed-tools`` as capability strings.

    ``allowed-tools`` pre-approves tools for the invoking turn without a
    permission prompt, so it is a capability grant the analyser must see.
    Upstream accepts a space- or comma-separated string or a YAML list.
    """
    capabilities: list[str] = []
    for key in ("allowed-tools", "disallowed-tools"):
        value = fm_data.get(key)
        if isinstance(value, str):
            tools = [t.strip() for t in re.split(r"[,\s]+", value) if t.strip()]
        elif isinstance(value, list):
            tools = [str(t).strip() for t in value if str(t).strip()]
        else:
            continue
        capabilities.extend(tools)
    return capabilities


def _extract_shell_commands(text: str) -> list[str]:
    """Extract shell commands from bash/shell code blocks.

    A code block is treated as shell if its language tag is one of:
    bash, sh, shell, zsh, or empty (untagged blocks are often shell).
    Each non-empty, non-comment line in such a block is a shell command.
    """
    shell_tags = {"bash", "sh", "shell", "zsh", ""}
    commands: list[str] = []
    for match in _CODE_BLOCK_PATTERN.finditer(text):
        lang = match.group(1).lower()
        if lang in shell_tags:
            block = match.group(2)
            for line in block.strip().splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    commands.append(stripped)
    return commands


class ClaudeSkillsParser(SkillParser):
    """Parser for Claude Code skills (``<skill-name>/SKILL.md``).

    Discovery follows the upstream Agent Skills layout documented at
    https://code.claude.com/docs/en/skills. A skill is a *directory*
    containing ``SKILL.md``; it is never a bare Markdown file:

    ===========  ====================================================
    Level        Path
    ===========  ====================================================
    Personal     ``~/.claude/skills/<skill-name>/SKILL.md``
    Project      ``.claude/skills/<skill-name>/SKILL.md``
    Plugin       ``<plugin>/skills/<skill-name>/SKILL.md``
    Legacy       ``.claude/commands/<name>.md``
    ===========  ====================================================

    Nested ``.claude/skills/`` directories below the root also load, so a
    monorepo package can ship skills that apply only within that package.
    A ``<skill-name>`` entry may be a symlink; the target is followed and
    loaded once even when reachable from several locations.

    Parse logic per skill:
        1. Read ``SKILL.md``.
        2. Extract YAML frontmatter; ``name`` defaults to the directory name.
        3. Record ``allowed-tools`` / ``disallowed-tools`` as declared
           capabilities -- these pre-approve tool use without prompting.
        4. Extract URLs, env vars, code blocks, and shell commands.
        5. Construct a ``ParsedSkill`` with format="claude".
    """

    def __init__(self, max_scan_depth: int = _MAX_SCAN_DEPTH) -> None:
        """Create a parser.

        Args:
            max_scan_depth: How many directory levels below the scan root to
                search for nested ``.claude`` directories. Scan cost grows
                sharply with depth on large trees; the default is tuned for
                interactive use.
        """
        self.max_scan_depth = max_scan_depth

    def can_parse(self, path: Path) -> bool:
        """Check whether the tree contains at least one Claude Code skill.

        Args:
            path: Root directory to probe.

        Returns:
            True if any ``SKILL.md`` or legacy command file is reachable.
        """
        return next(self._iter_skill_files(path), None) is not None

    def parse(self, path: Path) -> list[ParsedSkill]:
        """Parse every Claude Code skill reachable from ``path``.

        Args:
            path: Root directory to scan.

        Returns:
            List of ParsedSkill instances. Empty if no skills found.
        """
        results: list[ParsedSkill] = []
        for skill_file in self._iter_skill_files(path):
            skill = self._parse_file(skill_file)
            if skill is not None:
                results.append(skill)
        return results

    def _iter_skill_files(self, path: Path) -> Iterator[Path]:
        """Yield each distinct skill file exactly once, in stable order.

        De-duplication is keyed on the *resolved* path so that a skill
        reachable through several symlinked aliases is yielded once, matching
        upstream behaviour.
        """
        if not path.is_dir():
            return

        seen: set[Path] = set()
        for skills_root in self._iter_skill_roots(path, self.max_scan_depth):
            for skill_file in sorted(skills_root.glob(f"*/{_SKILL_FILENAME}")):
                resolved = _safe_resolve(skill_file)
                if resolved is None or resolved in seen:
                    continue
                seen.add(resolved)
                yield skill_file

        for commands_dir in sorted(
            _iter_dirs(path, f"{_CLAUDE_DIR}/{_COMMANDS_DIR}", self.max_scan_depth)
        ):
            for command_file in sorted(commands_dir.glob("*.md")):
                resolved = _safe_resolve(command_file)
                if resolved is None or resolved in seen:
                    continue
                seen.add(resolved)
                yield command_file

    @staticmethod
    def _iter_skill_roots(path: Path, max_depth: int = _MAX_SCAN_DEPTH) -> Iterator[Path]:
        """Yield every directory that may directly contain skill directories.

        Covers the project/personal root, nested ``.claude/skills/`` in
        monorepo packages, and plugin ``skills/`` directories.
        """
        # Project and personal: <root>/.claude/skills, plus nested packages.
        yield from _iter_dirs(path, f"{_CLAUDE_DIR}/{_SKILLS_DIR}", max_depth)
        # Plugins: <plugin>/skills/<skill-name>/SKILL.md
        yield from _iter_dirs(path, f"{_CLAUDE_DIR}/{_PLUGINS_DIR}/*/{_SKILLS_DIR}", max_depth)
        yield from _iter_dirs(path, f"{_CLAUDE_DIR}/{_PLUGINS_DIR}/*/*/{_SKILLS_DIR}", max_depth)

    def _parse_file(self, file_path: Path) -> ParsedSkill | None:
        """Parse a single Claude skill Markdown file.

        Args:
            file_path: Path to the .md file.

        Returns:
            A ParsedSkill, or None if the file cannot be read.
        """
        try:
            raw_content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

        # Upstream: `name` is optional and defaults to the *directory* name for
        # SKILL.md; legacy .claude/commands/<name>.md defaults to the filename.
        name = file_path.parent.name if file_path.name == _SKILL_FILENAME else file_path.stem
        description = ""
        declared_capabilities: list[str] = []
        frontmatter_match = _FRONTMATTER_PATTERN.match(raw_content)
        if frontmatter_match:
            try:
                fm_data = yaml.safe_load(frontmatter_match.group(1))
                if isinstance(fm_data, dict):
                    name = fm_data.get("name") or name
                    description = fm_data.get("description", "")
                    declared_capabilities = _declared_tool_capabilities(fm_data)
            except yaml.YAMLError:
                pass  # Keep directory-based defaults.

        # Extract security-relevant metadata from the full content.
        urls = _extract_urls(raw_content)
        env_vars = _extract_env_vars(raw_content)
        code_blocks = _extract_code_blocks(raw_content)
        shell_commands = _extract_shell_commands(raw_content)

        return ParsedSkill(
            name=name,
            version="unknown",
            source_path=file_path,
            format="claude",
            description=description,
            instructions=raw_content,
            declared_capabilities=declared_capabilities,
            urls=urls,
            env_vars_referenced=env_vars,
            code_blocks=code_blocks,
            shell_commands=shell_commands,
            raw_content=raw_content,
        )
