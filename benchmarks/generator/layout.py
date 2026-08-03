"""Single choke point for on-disk layout, sentinel text, and payload schema.

Malicious and benign specimens are produced by two independent class
hierarchies: :class:`benchmarks.generator.seeds.base.AttackPattern` and
:class:`benchmarks.generator.benign.base.BenignCategory`. Anything those
hierarchies implement separately is free to drift, and a detail that drifts
along the malicious/benign boundary becomes a feature perfectly correlated
with the label. A classifier can then score on the artefact instead of the
content, and the reported metric measures nothing.

Every specimen therefore passes through :func:`finalize` regardless of which
hierarchy produced it. Sentinel text, frontmatter schema, command schema and
file path are decided here and only here, so the two hierarchies cannot
diverge on them again.

Layout follows the `Agent Skills <https://agentskills.io>`_ open standard as
the runtimes actually install it, so that a scan of a specimen exercises the
same discovery path a scan of a real machine would:

===========  ==================================================================
Format       Specimen root contents
===========  ==================================================================
``claude``   ``.claude/skills/<name>/SKILL.md``
``openclaw`` ``.openclaw/skills/<name>/SKILL.md``
``mcp``      ``.mcp.json``
===========  ==================================================================
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Mapping

from .config import AUTHOR_POOL, NAME_BEARING_ATTACKS, SHARED_NAME_POOL
from .registry import JsonMcpDialect, MarkdownClaudeDialect, YamlOpenClawDialect

if TYPE_CHECKING:
    from .core import RenderedSkill, SkillSpec
    from .rng import DeterministicRNG


# =============================================================================
# Sentinel text — one string, every format, both classes
# =============================================================================

_SENTINEL_TEXT = (
    "SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification "
    "execution; do not execute. Licensed MIT."
)

#: Sentinel as it appears in a Markdown ``SKILL.md`` body.
SENTINEL_MARKDOWN = f"<!-- {_SENTINEL_TEXT} -->"

#: Key and value carrying the sentinel in an MCP JSON config.
SENTINEL_MCP_KEY = "_skillfortifybench_inert"
SENTINEL_MCP_VALUE = _SENTINEL_TEXT


# =============================================================================
# Layout constants
# =============================================================================

SKILL_FILENAME = "SKILL.md"
MCP_CONFIG_FILENAME = ".mcp.json"

#: Directory, relative to a specimen root, that each runtime loads skills from.
INSTALL_ROOTS: Mapping[str, str] = {
    "claude": ".claude/skills",
    "openclaw": ".openclaw/skills",
}

#: Markers that make a specimen need a given tool grant. Grants are derived
#: from what a specimen actually contains, by the same rule for both classes.
#:
#: Drawing grants at random instead would make almost every specimen declare
#: something other than what it does, so a least-privilege check would fire on
#: all of them and the resulting false-positive rate would measure the
#: generator's dice rather than the scanner.
_TOOL_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Bash", ("```bash", "```sh", "```shell", "```python", "```console")),
    ("WebFetch", ("http://", "https://", "curl ", "requests.", "urllib", "fetch(")),
    ("Write", ("open(", "shutil", " > ", ">>", "write_text", "cp ", "mv ", "rm ")),
)

#: Granted to every specimen. Each documents a workflow over local files, so
#: filesystem access is modelled as always declared and the least-privilege
#: check is left to fire on the capabilities the attacks actually hide: shell
#: and network.
_BASE_TOOLS: tuple[str, ...] = ("Read", "Write")

#: Neutral per-command summaries, shared by both classes for the same reason.
_COMMAND_SUMMARIES: tuple[str, ...] = (
    "Run this step from the skill directory.",
    "Invoke as part of the documented workflow.",
    "Execute when the described condition holds.",
    "Call this entry point to perform the task.",
    "Use the default arguments unless overridden.",
)


def declared_tools(content: str) -> list[str]:
    """Return the grants a specimen's own content calls for.

    Derived, not drawn: a declaration that matches the skill's behaviour is
    what a real author writes, and it leaves a least-privilege check to fire
    only on specimens that genuinely under-declare.
    """
    granted = set(_BASE_TOOLS)
    haystack = content.lower()
    for tool, markers in _TOOL_MARKERS:
        if any(marker in haystack for marker in markers):
            granted.add(tool)
    return sorted(granted)


# =============================================================================
# Path construction
# =============================================================================


def specimen_relative_path(fmt: str, skill_id: str, skill_name: str) -> str:
    """Return the path of a specimen's file, relative to its label directory.

    Every specimen owns a directory named for its ``skill_id`` and is a
    self-contained installation root beneath it, so one specimen scans as one
    unit and two specimens can never collide on skill name.
    """
    if fmt == "mcp":
        return f"{skill_id}/{MCP_CONFIG_FILENAME}"
    install_root = INSTALL_ROOTS.get(fmt)
    if install_root is None:
        raise NotImplementedError(f"unsupported format: {fmt}")
    return f"{skill_id}/{install_root}/{skill_name}/{SKILL_FILENAME}"


# =============================================================================
# Schema normalisation
# =============================================================================


def _normalize_commands(commands: Any, rng: "DeterministicRNG") -> list[dict]:
    """Give every command the same key set: name, command, description."""
    if not isinstance(commands, list):
        return []
    out: list[dict] = []
    for entry in commands:
        if not isinstance(entry, dict):
            continue
        description = entry.get("description")
        if not description:
            description = rng.choice(_COMMAND_SUMMARIES)
        out.append(
            {
                "name": entry.get("name", "run"),
                "command": entry.get("command", ""),
                "description": description,
            }
        )
    return out


def _render_command_sections(commands: list[dict]) -> str:
    """Render commands as Markdown sections with bash fences."""
    parts: list[str] = []
    for entry in commands:
        parts.append(f"### {entry['name']}\n")
        parts.append(f"{entry['description']}\n")
        parts.append("```bash\n" + str(entry["command"]).rstrip("\n") + "\n```\n")
    return "\n".join(parts)


def _openclaw_to_skill_md(
    payload: Mapping[str, object], rng: "DeterministicRNG"
) -> tuple[dict, str]:
    """Convert a legacy OpenClaw manifest payload into ``SKILL.md`` parts.

    The manifest fields map onto the published skill format: ``name`` and
    ``description`` become frontmatter, runtime dependencies become
    ``metadata.openclaw.requires.bins`` (the field the loader reads), and the
    command list becomes documented shell steps in the body. No command text
    is altered, so the specimen's behaviour is unchanged by the move.
    """
    name = str(payload.get("name", "skill"))
    frontmatter: dict[str, object] = {
        "name": name,
        "description": str(payload.get("description", "")),
    }
    version = payload.get("version")
    if version is not None:
        frontmatter["version"] = version
    frontmatter["author"] = payload.get("author") or rng.choice(AUTHOR_POOL)

    dependencies = payload.get("dependencies")
    if not isinstance(dependencies, list):
        dependencies = []
    frontmatter["metadata"] = {
        "openclaw": {"requires": {"bins": [str(d) for d in dependencies]}}
    }

    commands = _normalize_commands(payload.get("commands"), rng)

    body_parts: list[str] = [f"# {name}\n"]
    instructions = payload.get("instructions")
    if instructions:
        body_parts.append(str(instructions).strip() + "\n")
    if commands:
        body_parts.append("## Commands\n")
        body_parts.append(_render_command_sections(commands))
    return frontmatter, "\n".join(body_parts)


def _with_markdown_sentinel(body: str) -> str:
    """Prepend the sentinel to a Markdown body, exactly once."""
    stripped = body.lstrip("\n")
    if stripped.startswith(SENTINEL_MARKDOWN):
        return stripped
    return SENTINEL_MARKDOWN + "\n\n" + stripped


def inject_sentinel_mcp(payload: Mapping[str, object]) -> "OrderedDict[str, object]":
    """Insert the sentinel as the first key of an MCP payload, exactly once."""
    result: OrderedDict[str, object] = OrderedDict()
    result[SENTINEL_MCP_KEY] = SENTINEL_MCP_VALUE
    for key, value in payload.items():
        if key == SENTINEL_MCP_KEY:
            continue
        result[key] = value
    return result


# =============================================================================
# The choke point
# =============================================================================


def finalize(
    rendered: "RenderedSkill",
    spec: "SkillSpec",
    rng: "DeterministicRNG",
) -> "RenderedSkill":
    """Normalise a rendered specimen's schema, sentinel, and path.

    Accepts whatever either hierarchy produced, re-expresses it in the shared
    schema, and returns a replacement. Content is preserved verbatim: only
    field presence, ordering, and file placement are decided here.
    """
    fmt = spec.format

    if fmt == "mcp":
        payload = _normalize_mcp(JsonMcpDialect().parse(rendered.content_bytes), spec, rng)
        content = JsonMcpDialect().serialize(inject_sentinel_mcp(payload))
        skill_name = spec.skill_id
        extension = ".json"
    else:
        if fmt == "openclaw":
            frontmatter, body = _openclaw_payload(rendered.content_bytes, rng)
        elif fmt == "claude":
            frontmatter, body = _claude_payload(rendered.content_bytes)
        else:
            raise NotImplementedError(f"unsupported format: {fmt}")

        frontmatter = _normalize_frontmatter(frontmatter, body)
        original_name = str(frontmatter["name"])
        skill_name = _shared_name(original_name, spec, rng)
        if skill_name != original_name:
            # The name also appears in the heading and the prose, so rename
            # throughout: a leftover occurrence would reinstate the very
            # vocabulary split this replacement exists to remove.
            frontmatter["name"] = skill_name
            body = body.replace(original_name, skill_name)
        content = MarkdownClaudeDialect().serialize(
            {"frontmatter": frontmatter, "body": _with_markdown_sentinel(body)}
        )
        extension = ".md"

    return replace(
        rendered,
        filename=specimen_relative_path(fmt, spec.skill_id, skill_name),
        content_bytes=content,
        format_extension=extension,
    )


def _shared_name(current: str, spec: "SkillSpec", rng: "DeterministicRNG") -> str:
    """Return the specimen's skill name, drawn from the one shared pool.

    The rule is symmetric: any name already in the pool is kept, any name
    outside it is redrawn, and neither class is exempt. Applying this to one
    class only would leave the other holding names no specimen of the first
    can have, which separates them just as effectively. Attacks whose name
    carries the payload -- a typosquat is nothing but its name -- keep theirs.
    """
    if spec.is_malicious and spec.attack_type in NAME_BEARING_ATTACKS:
        return current
    if current in SHARED_NAME_POOL:
        return current
    return rng.choice(SHARED_NAME_POOL)


def _normalize_mcp(
    payload: "Mapping[str, object]", spec: "SkillSpec", rng: "DeterministicRNG"
) -> dict:
    """Apply the shared MCP schema: shared server names, no decorative keys."""
    out: dict[str, object] = {}
    for key, value in payload.items():
        if key in {"_comment", SENTINEL_MCP_KEY}:
            # Decorative and marker keys were emitted by one hierarchy only.
            continue
        if key == "mcpServers" and isinstance(value, dict):
            out[key] = {
                _shared_name(name, spec, rng): server for name, server in value.items()
            }
            continue
        out[key] = value
    return out


def _claude_payload(content_bytes: bytes) -> tuple[dict, str]:
    """Parse an already-serialised Claude specimen back into its parts."""
    parsed = MarkdownClaudeDialect().parse(content_bytes)
    frontmatter = dict(parsed["frontmatter"] or {})
    return frontmatter, str(parsed["body"])


def _openclaw_payload(content_bytes: bytes, rng: "DeterministicRNG") -> tuple[dict, str]:
    """Parse a legacy OpenClaw manifest and convert it to ``SKILL.md`` parts."""
    text = content_bytes.decode("utf-8")
    lines = [line for line in text.split("\n") if not line.startswith("#")]
    payload = YamlOpenClawDialect().parse("\n".join(lines).encode("utf-8")) or {}
    return _openclaw_to_skill_md(payload, rng)


def _normalize_frontmatter(frontmatter: Mapping[str, object], body: str) -> dict:
    """Apply the shared frontmatter schema in a fixed key order.

    ``allowed-tools`` is emitted for every specimen of both classes. It is the
    field the runtime reads to pre-authorise tools without a permission
    prompt, so a corpus in which only one class declares grants would let a
    scanner separate the classes on the field's presence alone.
    """
    out: dict[str, object] = {}
    out["name"] = frontmatter.get("name", "skill")
    out["description"] = frontmatter.get("description", "")

    # Grants use the runtime's real tool vocabulary and follow the specimen's
    # own content. An earlier ``capabilities`` field used invented names such
    # as ``read_env``, which no runtime grants and which only malicious
    # specimens carried -- so its values separated the classes even once the
    # key no longer did.
    out["allowed-tools"] = declared_tools(body)

    for key, value in frontmatter.items():
        if key in {"name", "description", "allowed-tools", "capabilities"}:
            continue
        out[key] = value
    return out
