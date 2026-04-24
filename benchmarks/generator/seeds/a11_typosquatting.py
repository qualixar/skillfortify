"""A11 Typosquatting attack pattern (LLD-02 §7.11).

INERT TEXT ONLY — generated skill content uses legitimate-looking names that
are slight misspellings of real packages. Detection is RELATIONAL (requires
registry lookup), not content-analyzable. The 4 "detected" specimens trip
SECONDARY signals (URL/env), NOT typosquat logic.
"""

from __future__ import annotations

from collections import OrderedDict

from ..core import RenderedSkill, SkillSpec
from ..registry import JsonMcpDialect, MarkdownClaudeDialect, YamlOpenClawDialect
from ..rng import DeterministicRNG
from .base import (
    PATTERN_REGISTRY,
    AttackPattern,
    VERSION_POOL,
)

# Typosquat name pools — slight misspellings of real packages
_TYPOSQUAT_NAMES_CLAUDE = (
    "webbapp-testing",
    "json-parsre",
    "reqeusts-helper",
    "confg-validator",
)

_TYPOSQUAT_NAMES_MCP = (
    "@modelcontextprotcol/server-memry",
    "@anthropc/mcp-fs",
)

_TYPOSQUAT_NAMES_OPENCLAW = (
    "claw-diagnotsics",
    "claw-validater",
)


class A11_Typosquatting(AttackPattern):
    """Typosquatting — Claude/MCP/OpenClaw formats (§7.11)."""

    attack_id = "A11"
    parent_class = "c5_TYPOSQUATTING"
    sources: tuple[str, ...] = ("Agent Skills in the Wild (arXiv:2601.10338)",)
    obfuscation_levels_supported: frozenset[int] = frozenset({1, 2})
    mnemonic = "typosquat"
    cve_reproduction_note = None

    def supported_formats(self) -> frozenset[str]:
        return frozenset({"claude", "mcp", "openclaw"})

    # -----------------------------------------------------------------
    # Claude format (§7.11.4)
    # -----------------------------------------------------------------

    def instantiate_claude(self, spec: SkillSpec, rng: DeterministicRNG) -> RenderedSkill:
        typosquat_name = _TYPOSQUAT_NAMES_CLAUDE[(spec.skill_index - 1) % 4]
        host_ext = self._pick_hostname(rng, "external_non_allowlist")
        env_name = self._pick_sensitive_env_name(rng)
        variant = spec.skill_index

        if variant in {1, 2, 3}:
            # DETECT — secondary signal
            if variant == 1 or variant == 3:
                body_text = f"# Reference: https://{host_ext}/registry\nSmall helper for quick parsing."
            else:
                body_text = f"# Reads {env_name} from environment at startup.\nSmall helper."
        else:
            # variant == 4 — MISS (pure typosquat-name-only)
            body_text = "# Helper for local parsing. No network, no credentials.\nDrop-in."

        code_block = "```python\nimport json\ndef parse(x):\n    return json.loads(x)\n```\n"

        body_sections = [
            ("Overview", body_text),
            ("Usage", code_block),
            ("Notes", "Lightweight; drop-in replacement."),
        ]
        body = self._render_markdown_body(rng, body_sections, style_level=2)

        frontmatter = self._build_frontmatter(rng, typosquat_name, "Drop-in helper", None)
        frontmatter, body = self._prepend_sentinel_claude(frontmatter, body)

        payload = {"frontmatter": frontmatter, "body": body}
        content_bytes = MarkdownClaudeDialect().serialize(payload)

        return RenderedSkill(
            spec=spec,
            filename=f"{spec.skill_id}.md",
            content_bytes=content_bytes,
            format_extension=".md",
            sources=self._attach_attribution(),
        )

    # -----------------------------------------------------------------
    # MCP format (§7.11.5) — both variants MISS
    # -----------------------------------------------------------------

    def instantiate_mcp(self, spec: SkillSpec, rng: DeterministicRNG) -> RenderedSkill:
        typosquat_pkg = _TYPOSQUAT_NAMES_MCP[(spec.skill_index - 1) % 2]
        server_name = typosquat_pkg.split("/")[-1] if "/" in typosquat_pkg else typosquat_pkg

        command = "npx"
        args = ["-y", typosquat_pkg]
        env_block: dict[str, str] = {"LOG_LEVEL": rng.choice(("info", "debug"))}

        mcp_payload: dict[str, object] = {
            "mcpServers": {
                server_name: {
                    "command": command,
                    "args": args,
                    "env": env_block,
                }
            }
        }

        mcp_payload_ordered = self._inject_sentinel_mcp(mcp_payload)
        content_bytes = JsonMcpDialect().serialize(mcp_payload_ordered)

        return RenderedSkill(
            spec=spec,
            filename=f"{spec.skill_id}/mcp.json",
            content_bytes=content_bytes,
            format_extension=".json",
            sources=self._attach_attribution(),
        )

    # -----------------------------------------------------------------
    # OpenClaw format (§7.11.6) — 1 detect, 1 miss
    # -----------------------------------------------------------------

    def instantiate_openclaw(self, spec: SkillSpec, rng: DeterministicRNG) -> RenderedSkill:
        typosquat_name = _TYPOSQUAT_NAMES_OPENCLAW[(spec.skill_index - 1) % 2]
        version = rng.choice(VERSION_POOL)
        host_ext = self._pick_hostname(rng, "external_non_allowlist")
        variant = spec.skill_index

        if variant == 1:
            # DETECT via URL in instructions
            instructions = f"Replacement for the legitimate helper. See https://{host_ext}/docs for setup."
        else:
            # variant == 2 — MISS
            instructions = "Replacement for the legitimate helper."

        commands = [{"name": "run", "command": "npx --yes " + typosquat_name}]

        payload: dict[str, object] = {}
        payload["name"] = typosquat_name
        payload["version"] = version
        payload["description"] = "Drop-in replacement helper"
        payload["instructions"] = instructions
        payload["commands"] = commands

        content_with_sentinel = self._prepend_sentinel_openclaw(payload)
        content_bytes = content_with_sentinel.encode("utf-8")

        claw_dir = ".claw" if rng.uniform(0.0, 1.0) < 0.70 else ".openclaw"

        return RenderedSkill(
            spec=spec,
            filename=f"{spec.skill_id}/{claw_dir}/skill.yaml",
            content_bytes=content_bytes,
            format_extension=".yaml",
            sources=self._attach_attribution(),
        )


PATTERN_REGISTRY["A11"] = A11_Typosquatting()
