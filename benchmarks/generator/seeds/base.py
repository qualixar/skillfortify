"""AttackPattern ABC + shared helpers + pool constants + sentinel constants.

Per LLD-02 §3-§6. INERT TEXT ONLY — string literals contain dangerous-looking
patterns as DATA for benchmark generation. No subprocess/socket/http/urllib
imports. AST scan (preflight.py) validates this at runtime.
"""

from __future__ import annotations

import base64
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..core import RenderedSkill, SkillSpec
    from ..rng import DeterministicRNG


# =============================================================================
# Sentinel constants (§5.2)
# =============================================================================

SENTINEL_CLAUDE_LINE: str = (
    "<!-- SKILLFORTIFYBENCH:INERT \u2014 arXiv:2603.00195 Appendix B "
    "specification execution; do not execute. Licensed MIT. -->"
)
SENTINEL_MCP_KEY: str = "_skillfortifybench_inert"
SENTINEL_MCP_VALUE: str = "SKILLFORTIFYBENCH:INERT arXiv:2603.00195 Appendix B; do not execute; MIT"
SENTINEL_OPENCLAW_LINE: str = (
    "# SKILLFORTIFYBENCH:INERT \u2014 arXiv:2603.00195 Appendix B "
    "specification execution; do not execute. Licensed MIT."
)

# =============================================================================
# Pool constants (minimal hardcoded tuples for A1+ to draw from)
# =============================================================================

NAME_POOL_LEGIT: tuple[str, ...] = (
    "diagnostics-helper", "env-reporter", "telemetry-agent", "metric-collector",
    "config-validator", "health-monitor", "log-rotator", "cache-warmer",
    "session-tracker", "perf-sampler", "status-beacon", "uptime-checker",
    "resource-inspector", "load-balancer-probe", "heartbeat-sender",
    "audit-logger", "event-emitter", "signal-handler", "task-scheduler",
    "data-aggregator", "schema-validator", "cert-checker", "dns-resolver",
    "rate-limiter", "circuit-breaker", "retry-handler", "batch-processor",
    "queue-monitor", "stream-collector", "digest-builder", "policy-enforcer",
)

NAME_POOL_MCP_SERVER: tuple[str, ...] = (
    "mcp-server-analytics", "mcp-server-sync", "mcp-server-metrics",
    "mcp-server-auth", "mcp-server-gateway", "mcp-server-proxy",
    "mcp-server-cache", "mcp-server-events", "mcp-server-logs",
    "mcp-server-config", "mcp-server-health", "mcp-server-registry",
    "mcp-server-broker", "mcp-server-relay", "mcp-server-bridge",
    "mcp-server-monitor", "mcp-server-scheduler", "mcp-server-ingestion",
    "mcp-server-pipeline", "mcp-server-dispatch", "mcp-server-collector",
)

NAME_POOL_OPENCLAW: tuple[str, ...] = (
    "claw-diagnostics", "claw-reporter", "claw-telemetry", "claw-collector",
    "claw-validator", "claw-monitor", "claw-rotator", "claw-warmer",
    "claw-tracker", "claw-sampler", "claw-beacon", "claw-checker",
    "claw-inspector", "claw-probe", "claw-heartbeat", "claw-logger",
    "claw-emitter", "claw-handler", "claw-scheduler", "claw-aggregator",
    "claw-schema", "claw-cert",
)

HOSTNAME_POOL_EXTERNAL: tuple[str, ...] = (
    "collector.evil.example.com", "metrics.attacker.example.com",
    "telemetry.malware.example.com", "data.exfil.example.com",
    "sink.bad.example.com", "ingest.rogue.example.com",
    "drop.hostile.example.com", "beacon.threat.example.com",
    "relay.adversary.example.com", "proxy.shadow.example.com",
    "c2.command.example.com", "callback.exploit.example.com",
    "stager.payload.example.com", "loader.backdoor.example.com",
    "tunnel.covert.example.com", "exfil.stealth.example.com",
    "harvest.phish.example.com", "redirect.spoof.example.com",
    "inject.sqli.example.com", "pivot.lateral.example.com",
    "keylog.sniff.example.com",
)

SENSITIVE_ENV_POOL: tuple[str, ...] = (
    "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "DATABASE_URL",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "STRIPE_SECRET_KEY",
    "SLACK_BOT_TOKEN", "SENDGRID_API_KEY", "TWILIO_AUTH_TOKEN",
    "DATADOG_API_KEY", "NPM_TOKEN", "DOCKER_PASSWORD",
    "GCP_SERVICE_ACCOUNT_KEY", "AZURE_CLIENT_SECRET",
    "SSH_PRIVATE_KEY", "JWT_SECRET",
)

DESCRIPTION_TEMPLATES: tuple[str, ...] = (
    "Lightweight {role} for internal {domain} monitoring.",
    "Periodic {role} that checks {domain} health status.",
    "Quick {role} to aggregate {domain} telemetry data.",
    "Silent {role} for {domain} performance sampling.",
    "Background {role} collecting {domain} diagnostics.",
    "Minimal {role} reporting {domain} uptime metrics.",
    "Helper {role} for {domain} configuration validation.",
    "Fast {role} scanning {domain} resource usage.",
    "Automated {role} tracking {domain} event streams.",
    "Compact {role} verifying {domain} certificate expiry.",
    "Routine {role} auditing {domain} access patterns.",
)

IMPORT_POOL_EXFIL: tuple[str, ...] = (
    "import os",
    "import json",
    "import requests",
    "import base64",
    "import hashlib",
    "import platform",
    "import sys",
    "import logging",
)

VERSION_POOL: tuple[str, ...] = (
    "0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.5.0",
    "1.0.0", "1.1.0", "1.2.0", "1.3.0",
    "2.0.0", "2.1.0", "2.3.1", "3.0.0",
)

_DESCRIPTION_ROLE_FILLS: tuple[str, ...] = (
    "agent", "daemon", "service", "worker", "probe",
)

_DESCRIPTION_DOMAIN_FILLS: tuple[str, ...] = (
    "cluster", "endpoint", "service", "node", "container",
)


# =============================================================================
# PATTERN_REGISTRY — populated by each subclass at import time
# =============================================================================

PATTERN_REGISTRY: dict[str, "AttackPattern"] = {}


# =============================================================================
# AttackPattern ABC
# =============================================================================


class AttackPattern(ABC):
    """Abstract base for all attack pattern seed generators (LLD-02 §3)."""

    attack_id: str
    parent_class: str
    sources: tuple[str, ...]
    obfuscation_levels_supported: frozenset[int]
    mnemonic: str
    cve_reproduction_note: str | None = None

    @abstractmethod
    def supported_formats(self) -> frozenset[str]:
        """Return the set of format strings this pattern can produce."""
        ...

    # -- dispatch --------------------------------------------------------------

    def instantiate(self, spec: "SkillSpec", rng: "DeterministicRNG") -> "RenderedSkill":
        """Dispatch to format-specific instantiator."""
        fmt = spec.format
        if fmt == "claude":
            return self.instantiate_claude(spec, rng)
        if fmt == "mcp":
            return self.instantiate_mcp(spec, rng)
        if fmt == "openclaw":
            return self.instantiate_openclaw(spec, rng)
        raise NotImplementedError(f"unsupported format: {fmt}")

    @abstractmethod
    def instantiate_claude(self, spec: "SkillSpec", rng: "DeterministicRNG") -> "RenderedSkill":
        ...

    @abstractmethod
    def instantiate_mcp(self, spec: "SkillSpec", rng: "DeterministicRNG") -> "RenderedSkill":
        ...

    @abstractmethod
    def instantiate_openclaw(self, spec: "SkillSpec", rng: "DeterministicRNG") -> "RenderedSkill":
        ...

    # -- canary ----------------------------------------------------------------

    def instantiate_canary(self, rng: "DeterministicRNG", format: str) -> "RenderedSkill":
        """Emit one representative specimen for canary dry-run (§5.4)."""
        from ..core import SkillSpec

        obf = (
            "L1" if 1 in self.obfuscation_levels_supported
            else f"L{min(self.obfuscation_levels_supported)}"
        )
        spec = SkillSpec(
            skill_id=f"canary_{self.attack_id}",
            format=format,
            is_malicious=True,
            attack_type=self.attack_id,
            parent_class=self.parent_class,
            benign_category=None,
            skill_index=1,
            obfuscation_level=obf,
            is_canary=True,
        )
        return self.instantiate(spec, rng)

    # -- shared helpers --------------------------------------------------------

    def _pick_name(self, rng: "DeterministicRNG", pool_key: str) -> str:
        if pool_key == "legit":
            return rng.choice(NAME_POOL_LEGIT)
        if pool_key == "mcp_server":
            return rng.choice(NAME_POOL_MCP_SERVER)
        if pool_key == "openclaw":
            return rng.choice(NAME_POOL_OPENCLAW)
        return rng.choice(NAME_POOL_LEGIT)

    def _pick_hostname(self, rng: "DeterministicRNG", kind: str) -> str:
        return rng.choice(HOSTNAME_POOL_EXTERNAL)

    def _pick_sensitive_env_name(self, rng: "DeterministicRNG") -> str:
        return rng.choice(SENSITIVE_ENV_POOL)

    def _pick_description(self, rng: "DeterministicRNG", benign_cover: bool = False) -> str:
        template = rng.choice(DESCRIPTION_TEMPLATES)
        role = rng.choice(_DESCRIPTION_ROLE_FILLS)
        domain = rng.choice(_DESCRIPTION_DOMAIN_FILLS)
        result = template.replace("{role}", role).replace("{domain}", domain)
        if benign_cover:
            _ = rng.choice(_DESCRIPTION_DOMAIN_FILLS)  # extra draw for determinism
        return result

    def _pick_imports(self, rng: "DeterministicRNG", role: str) -> list[str]:
        count = rng.randint(2, 4)
        selected = rng.sample(IMPORT_POOL_EXFIL, count)
        return list(selected)

    def _build_frontmatter(
        self,
        rng: "DeterministicRNG",
        name: str,
        description: str,
        capabilities: list[str] | None = None,
    ) -> dict[str, object]:
        fm: dict[str, object] = {}
        fm["name"] = name
        fm["description"] = description
        if capabilities is not None:
            fm["capabilities"] = capabilities
        return fm

    def _render_markdown_body(
        self,
        rng: "DeterministicRNG",
        sections: list[tuple[str, str]],
        style_level: int = 2,
    ) -> str:
        prefix = "#" * style_level
        parts: list[str] = []
        for heading, content in sections:
            parts.append(f"{prefix} {heading}\n\n{content}\n")
        return "\n".join(parts)

    def _humanize_code(self, rng: "DeterministicRNG", code: str) -> str:
        lines = code.split("\n")
        result: list[str] = []
        for line in lines:
            result.append(line)
            if rng.uniform(0.0, 1.0) < 0.15:
                result.append("")
        return "\n".join(result)

    # -- obfuscation layers ----------------------------------------------------

    def _obfuscate_L1(self, code: str) -> str:
        return code

    def _obfuscate_L2(self, rng: "DeterministicRNG", code: str) -> str:
        # Minor variable renaming (placeholder for L2)
        return code

    def _obfuscate_L3(self, rng: "DeterministicRNG", code: str) -> str:
        # Add misdirection comments
        return "# performance optimization\n" + code

    def _obfuscate_L4(self, rng: "DeterministicRNG", code: str) -> str:
        # String splitting placeholder
        return code

    # -- sentinel helpers (§5.3) -----------------------------------------------

    def _prepend_sentinel_claude(
        self, frontmatter: dict, body: str
    ) -> tuple[dict, str]:
        new_body = SENTINEL_CLAUDE_LINE + "\n\n" + body
        return (frontmatter, new_body)

    def _inject_sentinel_mcp(self, mcp_payload: dict) -> OrderedDict:
        result = OrderedDict()
        result[SENTINEL_MCP_KEY] = SENTINEL_MCP_VALUE
        for key in mcp_payload:
            result[key] = mcp_payload[key]
        return result

    def _prepend_sentinel_openclaw(self, yaml_payload: dict) -> str:
        from ..registry import YamlOpenClawDialect

        # Convert OrderedDict to plain dict for YAML SafeDumper compatibility
        plain = dict(yaml_payload)
        serialized = YamlOpenClawDialect().serialize(plain)
        return SENTINEL_OPENCLAW_LINE + "\n" + serialized.decode("utf-8")

    # -- attribution -----------------------------------------------------------

    def _attach_attribution(self) -> tuple[str, ...]:
        return self.sources

    # -- base64 helper for MISS variants (data encoding, not network) ----------

    @staticmethod
    def _base64_encode_string(value: str) -> str:
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
