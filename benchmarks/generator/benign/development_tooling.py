"""DevelopmentTooling benign category — populated Stage 6 T3 per LLD-03 §6.4.

INERT TEXT ONLY. No subprocess/socket/urllib/http imports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BenignCategory

if TYPE_CHECKING:
    from ..core import SkillSpec
    from ..rng import DeterministicRNG


class DevelopmentToolingCategory(BenignCategory):
    """Category 4: lint/test/build wrappers — pytest, eslint, ruff, coverage."""

    category_id: str = "development_tooling"
    name_pool: tuple[str, ...] = (
        "pytest-flake-reporter", "eslint-rule-counter", "ruff-preset-applier",
        "coverage-line-annotator", "mypy-stub-generator", "black-format-checker",
        "isort-import-sorter", "bandit-security-scanner", "pylint-score-tracker",
        "flake8-config-helper", "tox-env-lister", "pre-commit-hook-runner",
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
            "pytest -q --tb=short",
            "ruff check . --fix",
            "```\n",
            "## Details\n",
            "Wraps common development tools for linting and testing.",
            "Runs locally with no network access required.",
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
                    "args": ["-m", "pytest", "-q", "--tb=short"],
                    "env": {"PYTHONDONTWRITEBYTECODE": "1"},
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
                    "name": "lint",
                    "command": "ruff check . --output-format=json",
                    "description": "Run ruff linter on the current directory.",
                },
                {
                    "name": "test",
                    "command": "pytest -q --tb=short",
                    "description": "Run pytest with short traceback output.",
                },
            ],
        }
