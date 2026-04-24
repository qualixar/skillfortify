"""SystemInformation benign category — populated Stage 6 T3 per LLD-03 §6.5.

INERT TEXT ONLY. No subprocess/socket/urllib/http imports.
String literals containing shell commands are DATA for benchmark generation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BenignCategory

if TYPE_CHECKING:
    from ..core import SkillSpec
    from ..rng import DeterministicRNG


class SystemInformationCategory(BenignCategory):
    """Category 5: read-only platform/disk/memory/uptime queries."""

    category_id: str = "system_information"
    name_pool: tuple[str, ...] = (
        "uptime-reporter", "disk-usage-summary", "kernel-version-check",
        "free-memory-report", "cpu-info-collector", "hostname-resolver",
        "load-average-monitor", "swap-usage-checker", "os-release-reader",
        "network-iface-lister", "process-count-reporter", "env-path-inspector",
    )

    def instantiate_claude(
        self, spec: "SkillSpec", rng: "DeterministicRNG"
    ) -> dict[str, object]:
        name = self._pick_name(rng)
        desc = self._pick_description(rng)
        body_lines = [
            f"# {name}\n",
            f"{desc}\n",
            "## Usage\n",
            "```bash",
            "df -h",
            "uname -a",
            "python -c 'import platform; print(platform.platform())'",
            "```\n",
            "## Details\n",
            "Gathers read-only system information.",
            "No write operations, no network access.",
        ]
        return {
            "frontmatter": {"name": name, "description": desc},
            "body": "\n".join(body_lines),
        }

    def instantiate_mcp(
        self, spec: "SkillSpec", rng: "DeterministicRNG"
    ) -> dict[str, object]:
        name = self._pick_name(rng)
        desc = self._pick_description(rng)
        server_name = f"mcp-server-{name}"
        return {
            "mcpServers": {
                server_name: {
                    "command": "python",
                    "args": ["-c", "import platform; print(platform.platform())"],
                    "env": {"LANG": "en_US.UTF-8"},
                    "description": desc,
                }
            }
        }

    def instantiate_openclaw(
        self, spec: "SkillSpec", rng: "DeterministicRNG"
    ) -> dict[str, object]:
        name = self._pick_name(rng)
        desc = self._pick_description(rng)
        version = self._pick_version(rng)
        return {
            "name": name,
            "version": version,
            "description": desc,
            "commands": [
                {
                    "name": "disk-usage",
                    "command": "df -h",
                    "description": "Report filesystem disk space usage.",
                },
                {
                    "name": "system-info",
                    "command": "uname -a",
                    "description": "Print system kernel and architecture info.",
                },
            ],
        }
