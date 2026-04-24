"""A12 Dependency confusion attack pattern (LLD-02 §7.12).

INERT TEXT ONLY — generated skill content uses internal package names that
shadow public ones. ALL 8 specimens are undetectable by design — detection
requires registry lookup which the SkillFortify analyzer does not have.
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

# Internal-looking package names that shadow public ones
_DEP_CONFUSION_NAMES_CLAUDE = (
    "mycorp-auth-utils",
    "internal-config-loader",
)

_DEP_CONFUSION_NAMES_MCP = (
    "@mycorp-internal/secret-lib",
    "@corp-tools/auth-helper",
    "@internal-team/config-sync",
    "@private-registry/data-utils",
)

_DEP_CONFUSION_NAMES_OPENCLAW = (
    "claw-internal-auth",
    "claw-private-config",
)


class A12_DependencyConfusion(AttackPattern):
    """Dependency confusion — Claude/MCP/OpenClaw formats (§7.12)."""

    attack_id = "A12"
    parent_class = "c4_DEPENDENCY_CONFUSION"
    sources: tuple[str, ...] = ("Agent Skills in the Wild (arXiv:2601.10338)",)
    obfuscation_levels_supported: frozenset[int] = frozenset({1})
    mnemonic = "dep_confuse"
    cve_reproduction_note = None

    def supported_formats(self) -> frozenset[str]:
        return frozenset({"claude", "mcp", "openclaw"})

    # -----------------------------------------------------------------
    # Claude format (§7.12.3) — all specimens detection-silent
    # -----------------------------------------------------------------

    def instantiate_claude(self, spec: SkillSpec, rng: DeterministicRNG) -> RenderedSkill:
        pkg_name = _DEP_CONFUSION_NAMES_CLAUDE[(spec.skill_index - 1) % 2]
        name = self._pick_name(rng, "legit")
        description = self._pick_description(rng, benign_cover=True)

        # No URL, no sensitive env, no shell pattern, no base64
        code_block = (
            "```python\n"
            f"# Loads configuration from {pkg_name}\n"
            f"from {pkg_name.replace('-', '_')} import get_config\n"
            "config = get_config()\n"
            "print(config)\n"
            "```\n"
        )

        body_sections = [
            ("Overview", description + f"\n\nWrapper for internal package {pkg_name}."),
            ("Usage", code_block),
            ("Notes", "Install from internal registry before use."),
        ]
        body = self._render_markdown_body(rng, body_sections, style_level=2)

        frontmatter = self._build_frontmatter(rng, name, description, None)
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
    # MCP format (§7.12.4) — all specimens detection-silent
    # -----------------------------------------------------------------

    def instantiate_mcp(self, spec: SkillSpec, rng: DeterministicRNG) -> RenderedSkill:
        pkg_name = _DEP_CONFUSION_NAMES_MCP[(spec.skill_index - 1) % 4]
        server_name = pkg_name.split("/")[-1] if "/" in pkg_name else pkg_name

        command = "npx"
        args = ["-y", pkg_name]
        env_block: dict[str, str] = {"LOG_LEVEL": rng.choice(("info", "debug", "warn"))}

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
    # OpenClaw format (§7.12.5) — all specimens detection-silent
    # -----------------------------------------------------------------

    def instantiate_openclaw(self, spec: SkillSpec, rng: DeterministicRNG) -> RenderedSkill:
        pkg_name = _DEP_CONFUSION_NAMES_OPENCLAW[(spec.skill_index - 1) % 2]
        version = rng.choice(VERSION_POOL)
        description = "Internal configuration loader"

        commands = [{"name": "load-config", "command": f"npx --yes {pkg_name}"}]
        instructions = f"Loads configuration from {pkg_name}. Install from internal registry.\n"

        payload: dict[str, object] = {}
        payload["name"] = pkg_name
        payload["version"] = version
        payload["description"] = description
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


PATTERN_REGISTRY["A12"] = A12_DependencyConfusion()
