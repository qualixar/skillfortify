"""ApiIntegration benign category — populated Stage 6 T3 per LLD-03 §6.3.

INERT TEXT ONLY. No subprocess/socket/urllib/http imports.
String literals containing URLs are DATA for benchmark generation, not live calls.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BenignCategory

if TYPE_CHECKING:
    from ..core import SkillSpec
    from ..rng import DeterministicRNG


# Allow-listed URL templates (DATA only, never fetched).
_API_URL_POOL: tuple[str, ...] = (
    "https://api.github.com/repos/{owner}/{repo}",
    "https://api.github.com/users/{user}/repos",
    "https://pypi.org/pypi/{package}/json",
    "https://registry.npmjs.org/{package}",
    "https://api.github.com/repos/{owner}/{repo}/issues",
    "https://pypi.org/simple/{package}/",
)


class ApiIntegrationCategory(BenignCategory):
    """Category 3: REST clients limited to allow-listed hosts only."""

    category_id: str = "api_integration"
    name_pool: tuple[str, ...] = (
        "pypi-version-probe", "github-issue-summarizer", "npm-meta-fetch",
        "docs-python-link-check", "github-repo-stats", "pypi-download-counter",
        "npm-dep-tree-viewer", "github-release-checker", "pypi-license-scanner",
        "npm-audit-reporter", "github-star-tracker", "registry-health-check",
    )

    def instantiate_claude(
        self, spec: "SkillSpec", rng: "DeterministicRNG"
    ) -> dict[str, object]:
        name = self._pick_name(rng)
        desc = self._pick_description(rng)
        url_template = rng.choice(_API_URL_POOL)
        body_lines = [
            f"# {name}\n",
            f"{desc}\n",
            "## Usage\n",
            "```bash",
            f'curl -s "{url_template}" | python -m json.tool',
            "```\n",
            "## Notes\n",
            "Queries public APIs for package and repository metadata.",
            "Only communicates with allow-listed hosts: github.com, pypi.org, npmjs.org.",
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
                    "args": ["-m", "pip", "index", "versions", "requests"],
                    "env": {"PIP_NO_INPUT": "1"},
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
        url_template = rng.choice(_API_URL_POOL)
        return {
            "name": name,
            "version": version,
            "description": desc,
            "commands": [
                {
                    "name": "fetch-metadata",
                    "command": f'curl -s "{url_template}"',
                    "description": "Fetch public metadata from an allow-listed API.",
                },
                {
                    "name": "check-version",
                    "command": "python -m pip index versions pip",
                    "description": "Check available versions of a package on PyPI.",
                },
            ],
        }
