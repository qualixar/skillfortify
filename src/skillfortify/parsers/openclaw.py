"""Parser for OpenClaw skills (``<skill-name>/SKILL.md``).

OpenClaw is the largest open-source agent framework. Its skills use the
`Agent Skills <https://agentskills.io>`_ open standard -- the same format
Claude Code, Codex CLI, and other runtimes use -- so a skill is a *directory*
containing ``SKILL.md``: YAML frontmatter followed by markdown instructions.

.. code-block:: yaml

    ---
    name: web-scraper
    description: Scrapes web pages and extracts structured data
    version: 1.3.0
    metadata:
      openclaw:
        requires:
          env: [SCRAPER_API_KEY]
          bins: [curl]
    ---

Load locations (verified against https://docs.openclaw.ai/tools/skills and
https://github.com/openclaw/clawhub/blob/main/docs/skill-format.md on
2026-08-03):

- ``~/.openclaw/skills/`` -- managed and local skills
- ``<workspace>/skills/`` -- workspace skills (highest precedence)
- ``.openclaw/skills/``   -- project skills at a repo root
- bundled skills shipped with the install

Discovery recurses below each root, so ``skills/research/SKILL.md`` and
``skills/personal/research/SKILL.md`` are both found; the folder path is
organisational only.

Security Relevance
------------------
OpenClaw's marketplace, ClawHub, was the target of the ClawHavoc campaign
(January-February 2026), disclosed by Koi Security (Oren Yomtov, 1 Feb 2026):
of 2,857 skills then available, 341 were malicious and 335 traced to a single
coordinated operation. Antiy CERT's subsequent analysis counted at least 1,184
malicious skills published historically. Palo Alto Unit 42 found evasive
skills still present through May 2026.

The parser extracts the signals those campaigns exercised:

- **URLs** from instructions and commands -- exfiltration endpoints.
- **Environment variables**, both referenced in the body and declared in
  ``metadata.openclaw.requires.env`` -- credential exposure.
- **Shell commands** from fenced code blocks -- code execution surface.
- **Required binaries** from ``requires.bins`` -- execution dependencies.

References:
    Koi Security, ClawHub audit (Feb 2026); Antiy CERT, "ClawHavoc: Analysis
    of a Large-Scale Poisoning Campaign Targeting the OpenClaw Skill Market".

    Jiang et al., "SoK: Agentic Skills -- Beyond Tool Use in LLM Agents"
    (arXiv:2602.20867, 24 Feb 2026). Seven skill design patterns.

    Hu et al., "MalTool: Malicious Tool Attacks on LLM Agents"
    (arXiv:2602.12194, 12 Feb 2026). 1,300 standalone malicious tools plus
    5,727 real-world tools with embedded malicious behaviour.

    Layout verified against the published skill-format specification; see
    ``tests/parsers/test_openclaw_conformance.py``.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import yaml

from skillfortify.parsers import treewalk
from skillfortify.parsers.base import ParsedSkill, SkillParser

# ---------------------------------------------------------------------------
# Upstream layout constants
# ---------------------------------------------------------------------------

# A skill is a directory containing this file, never a standalone YAML file.
_SKILL_FILENAME = "SKILL.md"

# The install-root marker. A repository may hold several: one at the top and
# one per package, so it is searched for at depth.
_OPENCLAW_DIR = ".openclaw"

# Skill directories live under this, relative to each ``.openclaw`` found.
_SKILLS_SUBDIR = "skills"

# Upstream also honours a bare ``skills/`` directory, but only for a root the
# user named explicitly. Re-anchoring that onto every directory in a tree
# would claim any unrelated ``skills/`` folder, so it stays root-only.
_ROOT_ONLY_SKILL_ROOTS = ("skills",)

# Upstream discovers SKILL.md up to six levels below a configured root.
_MAX_SKILL_DEPTH = 6

# Directories that never contain skills; pruned to keep scans bounded.
_PRUNED_DIR_NAMES = treewalk.PRUNED_DIR_NAMES

# ---------------------------------------------------------------------------
# Extraction patterns
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(r"https?://[^\s\"'`)\]>]+")

_ENV_VAR_PATTERN = re.compile(
    r"""(?:"""
    r"""\$\{?([A-Z][A-Z0-9_]{1,})\}?"""
    # An underscore is required so that capitalised prose words are not read
    # as environment variables; sigil forms above still catch $PATH.
    r"""|(?:^|[\s=:])([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)(?=[=\s"'`])"""
    r""")""",
    re.MULTILINE,
)

_CODE_BLOCK_PATTERN = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)

_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

_SHELL_TAGS = {"bash", "sh", "shell", "zsh", ""}


def _extract_urls(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from text."""
    return _URL_PATTERN.findall(text)


def _extract_env_vars(text: str) -> list[str]:
    """Extract unique environment variable names from text."""
    found: set[str] = set()
    for match in _ENV_VAR_PATTERN.finditer(text):
        for group in match.groups():
            if group:
                found.add(group)
    return sorted(found)


def _extract_code_blocks(text: str) -> list[str]:
    """Extract the content of all fenced code blocks."""
    return [match.group(2) for match in _CODE_BLOCK_PATTERN.finditer(text)]


def _extract_shell_commands(text: str) -> list[str]:
    """Extract shell command lines from shell-tagged fenced code blocks."""
    commands: list[str] = []
    for match in _CODE_BLOCK_PATTERN.finditer(text):
        if match.group(1).lower() not in _SHELL_TAGS:
            continue
        for line in match.group(2).strip().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                commands.append(stripped)
    return commands


def _openclaw_requirements(fm_data: dict[str, object]) -> tuple[list[str], list[str]]:
    """Return ``(required_env, required_bins)`` from ``metadata.openclaw``.

    Upstream nests runtime requirements under ``metadata.openclaw.requires``,
    with ``env`` naming required environment variables and ``bins`` naming
    required executables. Both are declared attack surface: the first is
    credential access, the second is execution capability.
    """
    metadata = fm_data.get("metadata")
    if not isinstance(metadata, dict):
        return [], []
    openclaw = metadata.get("openclaw")
    if not isinstance(openclaw, dict):
        return [], []
    requires = openclaw.get("requires")
    if not isinstance(requires, dict):
        return [], []

    def _as_list(value: object) -> list[str]:
        if isinstance(value, str):
            return [v.strip() for v in re.split(r"[,\s]+", value) if v.strip()]
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        return []

    return _as_list(requires.get("env")), _as_list(requires.get("bins"))


class OpenClawParser(SkillParser):
    """Parser for OpenClaw skill directories containing ``SKILL.md``.

    Discovery logic:
        1. Locate candidate roots: ``.openclaw/skills/`` and ``skills/``,
           at the scan root or nested below it.
        2. Find ``SKILL.md`` at any depth under those roots, bounded by
           ``_MAX_SKILL_DEPTH``.
        3. ``can_parse()`` is True when at least one such file exists.

    Parse logic per skill:
        1. Read ``SKILL.md`` and split YAML frontmatter from the body.
        2. Read ``name`` (defaulting to the directory name), ``description``,
           and ``version``.
        3. Merge declared ``requires.env`` with env vars referenced in the body.
        4. Extract URLs, shell commands, and code blocks from the body.
    """

    def can_parse(self, path: Path) -> bool:
        """Check whether the tree contains at least one OpenClaw skill."""
        return next(self._iter_skill_files(path), None) is not None

    def parse(self, path: Path) -> list[ParsedSkill]:
        """Parse every OpenClaw skill reachable from ``path``."""
        results: list[ParsedSkill] = []
        for skill_file in self._iter_skill_files(path):
            skill = self._parse_file(skill_file)
            if skill is not None:
                results.append(skill)
        return results

    def _iter_skill_files(self, path: Path) -> Iterator[Path]:
        """Yield each distinct ``SKILL.md`` exactly once, in stable order."""
        if not path.is_dir():
            return

        seen: set[Path] = set()
        for skills_root in self._iter_skill_roots(path):
            for skill_file in sorted(_iter_skill_md(skills_root, _MAX_SKILL_DEPTH)):
                try:
                    resolved = skill_file.resolve(strict=True)
                except (OSError, RuntimeError):
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                yield skill_file

    @staticmethod
    def _iter_skill_roots(path: Path) -> Iterator[Path]:
        """Yield every directory that may contain OpenClaw skill directories.

        Searches the tree for ``.openclaw`` install roots, so skills held in
        ``packages/*/.openclaw/skills`` are covered by a single scan of the
        top level, then adds the root-only ``skills/`` convention.
        """
        for openclaw_dir in treewalk.iter_marker_dirs(path, _OPENCLAW_DIR):
            candidate = openclaw_dir / _SKILLS_SUBDIR
            if candidate.is_dir():
                yield candidate

        for relative in _ROOT_ONLY_SKILL_ROOTS:
            candidate = path / relative
            if candidate.is_dir():
                yield candidate

    def _parse_file(self, file_path: Path) -> ParsedSkill | None:
        """Parse a single OpenClaw ``SKILL.md``.

        Args:
            file_path: Path to the SKILL.md file.

        Returns:
            A ParsedSkill, or None if the file cannot be read.
        """
        try:
            raw_content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

        name = file_path.parent.name
        description = ""
        version = "unknown"
        required_env: list[str] = []
        required_bins: list[str] = []

        frontmatter_match = _FRONTMATTER_PATTERN.match(raw_content)
        body = raw_content[frontmatter_match.end() :] if frontmatter_match else raw_content
        if frontmatter_match:
            try:
                fm_data = yaml.safe_load(frontmatter_match.group(1))
            except yaml.YAMLError:
                fm_data = None
            if isinstance(fm_data, dict):
                name = fm_data.get("name") or name
                description = fm_data.get("description", "") or ""
                if fm_data.get("version") is not None:
                    version = str(fm_data["version"])
                required_env, required_bins = _openclaw_requirements(fm_data)

        env_vars = sorted(set(_extract_env_vars(body)) | set(required_env))

        return ParsedSkill(
            name=str(name),
            version=version,
            source_path=file_path,
            format="openclaw",
            description=str(description),
            instructions=body,
            dependencies=required_bins,
            code_blocks=_extract_code_blocks(body),
            urls=_extract_urls(body),
            env_vars_referenced=env_vars,
            shell_commands=_extract_shell_commands(body),
            raw_content=raw_content,
        )


def _iter_skill_md(root: Path, max_depth: int) -> Iterator[Path]:
    """Yield every ``SKILL.md`` at or below ``root``, bounded by ``max_depth``."""
    frontier = [(root, 0)]
    while frontier:
        current, depth = frontier.pop(0)
        try:
            entries = sorted(current.iterdir())
        except (OSError, PermissionError):
            continue

        for entry in entries:
            if entry.is_file() and entry.name == _SKILL_FILENAME:
                yield entry
            elif (
                entry.is_dir()
                and depth < max_depth
                and entry.name not in _PRUNED_DIR_NAMES
                and not entry.name.startswith(".")
            ):
                frontier.append((entry, depth + 1))
