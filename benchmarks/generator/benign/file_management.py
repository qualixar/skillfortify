"""FileManagement benign category — populated Stage 6 T3 per LLD-03 §6.1.

INERT TEXT ONLY. No subprocess/socket/urllib/http imports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BenignCategory

if TYPE_CHECKING:
    from ..core import SkillSpec
    from ..rng import DeterministicRNG


class FileManagementCategory(BenignCategory):
    """Category 1: local file I/O — pathlib, shutil, json, yaml file ops."""

    category_id: str = "file_management"
    name_pool: tuple[str, ...] = (
        "text-file-deduper", "dir-tree-summarizer", "yaml-merger",
        "csv-row-counter", "file-hash-report", "json-lint-helper",
        "path-normalizer", "file-size-reporter", "log-file-rotator",
        "config-file-validator", "archive-extractor", "temp-dir-cleaner",
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
            "python -m json.tool input.json output.json",
            "```\n",
            "## Details\n",
            "Uses pathlib and shutil for safe file operations.",
            "Reads input files, processes content, writes output.",
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
                    "args": ["-m", "json.tool", "--sort-keys"],
                    "env": {"LOG_LEVEL": "info"},
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
                    "name": "list-files",
                    "command": "find . -name '*.json' -type f",
                    "description": "List JSON files in the current directory tree.",
                },
                {
                    "name": "validate-json",
                    "command": "python -m json.tool --no-ensure-ascii",
                    "description": "Validate and pretty-print a JSON file.",
                },
            ],
        }
