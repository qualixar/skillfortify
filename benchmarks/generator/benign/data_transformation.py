"""DataTransformation benign category — populated Stage 6 T3 per LLD-03 §6.2.

INERT TEXT ONLY. No subprocess/socket/urllib/http imports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BenignCategory

if TYPE_CHECKING:
    from ..core import SkillSpec
    from ..rng import DeterministicRNG


class DataTransformationCategory(BenignCategory):
    """Category 2: format conversion — csv-to-json, yaml-to-json, XML pretty-print."""

    category_id: str = "data_transformation"
    name_pool: tuple[str, ...] = (
        "csv-to-json-converter", "yaml-to-json-bridge", "xml-pretty-printer",
        "json-formatter", "csv-to-tsv-converter", "base-converter",
        "tsv-normalizer", "markdown-table-formatter", "ini-to-yaml-bridge",
        "toml-to-json-converter", "ndjson-splitter", "jsonl-merger",
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
            "python -c 'import csv, json, sys; "
            "reader=csv.DictReader(sys.stdin); "
            "print(json.dumps(list(reader), indent=2))'",
            "```\n",
            "## Notes\n",
            "Converts between common data formats.",
            "Reads from stdin, writes to stdout.",
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
                    "args": ["-c", "import json, sys; json.dump(json.load(sys.stdin), sys.stdout, indent=2)"],
                    "env": {"PYTHONIOENCODING": "utf-8"},
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
                    "name": "convert",
                    "command": "python -m json.tool",
                    "description": "Convert and pretty-print JSON data.",
                },
                {
                    "name": "validate",
                    "command": "python -c 'import yaml, sys; yaml.safe_load(sys.stdin)'",
                    "description": "Validate YAML input from stdin.",
                },
            ],
        }
