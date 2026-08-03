"""BenignCategory ABC — populated Stage 6 T3 per LLD-03 §5.

INERT TEXT ONLY. No subprocess/socket/urllib/http imports.
AST scan (preflight.py) validates this at runtime.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import TYPE_CHECKING, Mapping

from ..config import FORMAT_EXTENSIONS
from ..layout import finalize, inject_sentinel_mcp
from ..seeds.base import (
    SENTINEL_CLAUDE_LINE,
    SENTINEL_MCP_KEY,
    SENTINEL_MCP_VALUE,
    SENTINEL_OPENCLAW_LINE,
)

if TYPE_CHECKING:
    from ..core import RenderedSkill, SkillSpec
    from ..rng import DeterministicRNG


# =============================================================================
# BenignCategory ABC
# =============================================================================


class BenignCategory(ABC):
    """Abstract base for all benign category generators (LLD-03 §5)."""

    category_id: str
    name_pool: tuple[str, ...]
    sources: tuple[str, ...] = ("SkillFortifyBench (arXiv:2603.00195)",)

    # -- protocol method -------------------------------------------------------

    def supported_formats(self) -> frozenset[str]:
        """Return the set of format strings this category can produce."""
        return frozenset({"claude", "mcp", "openclaw"})

    # -- dispatch --------------------------------------------------------------

    def instantiate(self, spec: "SkillSpec", rng: "DeterministicRNG") -> "RenderedSkill":
        """Dispatch to format-specific instantiator, then normalise.

        The result passes through :func:`..layout.finalize`, which both
        hierarchies share, so schema and file placement cannot drift along the
        malicious/benign boundary and become a label signal.
        """
        from ..core import RenderedSkill
        from ..registry import (
            JsonMcpDialect,
            MarkdownClaudeDialect,
            YamlOpenClawDialect,
        )

        fmt = spec.format

        if fmt == "claude":
            payload = self.instantiate_claude(spec, rng)
            payload = self._inject_sentinel_claude(payload)
            content_bytes = MarkdownClaudeDialect().serialize(payload)
        elif fmt == "mcp":
            payload = self.instantiate_mcp(spec, rng)
            payload = self._inject_sentinel_mcp(payload)
            content_bytes = JsonMcpDialect().serialize(payload)
        elif fmt == "openclaw":
            payload = self.instantiate_openclaw(spec, rng)
            content_bytes = self._serialize_openclaw_with_sentinel(payload)
        else:
            raise NotImplementedError(f"unsupported format: {fmt}")

        ext = FORMAT_EXTENSIONS[fmt]
        rendered = RenderedSkill(
            spec=spec,
            filename=spec.skill_id + ext,
            content_bytes=content_bytes,
            format_extension=ext,
            sources=self.sources,
        )
        return finalize(rendered, spec, rng)

    # -- abstract per-format methods -------------------------------------------

    @abstractmethod
    def instantiate_claude(
        self, spec: "SkillSpec", rng: "DeterministicRNG"
    ) -> dict[str, object]:
        """Return payload for MarkdownClaudeDialect: {frontmatter: {...}, body: "..."}."""
        ...

    @abstractmethod
    def instantiate_mcp(
        self, spec: "SkillSpec", rng: "DeterministicRNG"
    ) -> dict[str, object]:
        """Return payload for JsonMcpDialect: {mcpServers: {...}}."""
        ...

    @abstractmethod
    def instantiate_openclaw(
        self, spec: "SkillSpec", rng: "DeterministicRNG"
    ) -> dict[str, object]:
        """Return payload for YamlOpenClawDialect: {name: ..., version: ..., ...}."""
        ...

    # -- sentinel injection helpers --------------------------------------------

    @staticmethod
    def _inject_sentinel_claude(payload: dict[str, object]) -> dict[str, object]:
        """Prepend SKILLFORTIFYBENCH:INERT sentinel to Claude body text."""
        body = str(payload.get("body", ""))
        new_body = SENTINEL_CLAUDE_LINE + "\n\n" + body
        return {**payload, "body": new_body}

    @staticmethod
    def _inject_sentinel_mcp(payload: dict[str, object]) -> OrderedDict:
        """Insert the sentinel key as the first entry of an MCP JSON payload.

        Delegates to the shared implementation so that the marker is
        byte-identical to the one malicious specimens carry.
        """
        return inject_sentinel_mcp(payload)

    @staticmethod
    def _serialize_openclaw_with_sentinel(payload: dict[str, object]) -> bytes:
        """Serialize OpenClaw YAML with sentinel comment prepended."""
        from ..registry import YamlOpenClawDialect

        serialized = YamlOpenClawDialect().serialize(dict(payload))
        text = SENTINEL_OPENCLAW_LINE + "\n" + serialized.decode("utf-8")
        return text.encode("utf-8")

    # -- shared helpers --------------------------------------------------------

    def _pick_name(self, rng: "DeterministicRNG") -> str:
        """Pick a deterministic name from the category name pool."""
        return rng.choice(self.name_pool)

    def _pick_description(self, rng: "DeterministicRNG") -> str:
        """Pick a deterministic short description."""
        templates = (
            "Lightweight helper for local {domain} operations.",
            "Quick utility to process {domain} data.",
            "Simple tool for {domain} management tasks.",
            "Minimal helper for {domain} inspection.",
            "Fast utility scanning {domain} resources.",
            "Automated helper for {domain} workflows.",
            "Compact tool verifying {domain} state.",
            "Routine utility auditing {domain} info.",
        )
        domains = (
            "file", "project", "system", "config", "build",
            "test", "data", "package", "environment", "report",
        )
        template = rng.choice(templates)
        domain = rng.choice(domains)
        return template.replace("{domain}", domain)

    def _pick_version(self, rng: "DeterministicRNG") -> str:
        """Pick a deterministic semver version string."""
        versions = (
            "0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.5.0",
            "1.0.0", "1.1.0", "1.2.0", "1.3.0",
            "2.0.0", "2.1.0", "2.3.1", "3.0.0",
        )
        return rng.choice(versions)
