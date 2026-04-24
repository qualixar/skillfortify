"""Plugin protocols + canonical format dialects (LLD-01 §6.5-§6.7 + §7.5-§7.7).

No attack-pattern realizations here (those are T2/T3). This module only hosts
the typing Protocols and the three concrete FormatDialect classes.
"""

from __future__ import annotations

import json
from typing import (
    Any,
    Mapping,
    Protocol,
    runtime_checkable,
)

import yaml


# -----------------------------------------------------------------------------
# Plugin protocols
# -----------------------------------------------------------------------------


@runtime_checkable
class AttackPatternProtocol(Protocol):
    """Plugin contract for malicious skill realizations (§6.5)."""

    attack_id: str
    parent_class: str
    sources: tuple[str, ...]

    def supported_formats(self) -> frozenset: ...

    def instantiate(self, spec: Any, rng: Any) -> Any: ...


@runtime_checkable
class BenignCategoryProtocol(Protocol):
    """Plugin contract for benign skill realizations (§6.6)."""

    category_id: str

    def supported_formats(self) -> frozenset: ...

    def instantiate(self, spec: Any, rng: Any) -> Any: ...


# -----------------------------------------------------------------------------
# Canonical YAML dumper (shared by YAML + Markdown dialects)
# -----------------------------------------------------------------------------


class _NoAliasSafeDumper(yaml.SafeDumper):
    """SafeDumper that refuses to emit anchors/aliases (deterministic emission)."""


def _ignore_aliases(self, data):  # noqa: ANN001, ANN002
    return True


_NoAliasSafeDumper.ignore_aliases = _ignore_aliases  # type: ignore[assignment]


def _normalize_text(text: str) -> str:
    """CRLF→LF, lone CR→LF, and strip trailing whitespace on each line."""
    # Order: CRLF first, then lone CR.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    out_lines = [line.rstrip() for line in text.split("\n")]
    return "\n".join(out_lines)


def _strip_bom(encoded: bytes) -> bytes:
    BOM = b"\xef\xbb\xbf"
    if encoded.startswith(BOM):
        return encoded[len(BOM):]
    return encoded


# -----------------------------------------------------------------------------
# Format dialects
# -----------------------------------------------------------------------------


class JsonMcpDialect:
    """Canonical JSON serializer for MCP format (§7.5)."""

    extension: str = ".json"

    def serialize(self, payload: Mapping[str, object]) -> bytes:
        body = json.dumps(
            payload,
            indent=2,
            sort_keys=False,
            ensure_ascii=False,
            separators=(",", ": "),
            allow_nan=False,
        )
        body = _normalize_text(body)
        if not body.endswith("\n"):
            body = body + "\n"
        return _strip_bom(body.encode("utf-8"))

    def parse(self, content_bytes: bytes) -> Mapping[str, object]:
        return json.loads(content_bytes.decode("utf-8"))


class YamlOpenClawDialect:
    """Canonical YAML serializer for OpenClaw format (§7.6)."""

    extension: str = ".yaml"

    def serialize(self, payload: Mapping[str, object]) -> bytes:
        dumped = yaml.dump(
            payload,
            Dumper=_NoAliasSafeDumper,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=10**9,
            indent=2,
            explicit_start=False,
            explicit_end=False,
            line_break="\n",
        )
        dumped = _normalize_text(dumped)
        if not dumped.endswith("\n"):
            dumped = dumped + "\n"
        return _strip_bom(dumped.encode("utf-8"))

    def parse(self, content_bytes: bytes) -> Mapping[str, object]:
        return yaml.safe_load(content_bytes.decode("utf-8"))


class MarkdownClaudeDialect:
    """Canonical Markdown + YAML-frontmatter serializer for Claude format (§7.7).

    Input payload shape: {"frontmatter": Mapping, "body": str}.
    """

    extension: str = ".md"

    def serialize(self, payload: Mapping[str, object]) -> bytes:
        fm_obj = payload["frontmatter"]
        body_str_in = payload["body"]
        if not isinstance(body_str_in, str):
            raise TypeError("body must be a str")

        fm_body = yaml.dump(
            fm_obj,
            Dumper=_NoAliasSafeDumper,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            indent=2,
            width=10**9,
            line_break="\n",
        )
        fm_body = _normalize_text(fm_body)
        if fm_body.endswith("\n"):
            fm_body = fm_body[:-1]
        frontmatter = "---\n" + fm_body + "\n---\n"

        body_str = _normalize_text(body_str_in)
        if not body_str.endswith("\n"):
            body_str = body_str + "\n"

        full = frontmatter + "\n" + body_str
        return _strip_bom(full.encode("utf-8"))

    def parse(self, content_bytes: bytes) -> Mapping[str, object]:
        text = content_bytes.decode("utf-8")
        if not text.startswith("---\n"):
            raise ValueError("Markdown claude dialect requires YAML frontmatter")
        end = text.find("\n---\n", 4)
        if end < 0:
            raise ValueError("unterminated YAML frontmatter")
        fm_text = text[4:end]
        body = text[end + len("\n---\n"):]
        if body.startswith("\n"):
            body = body[1:]
        fm = yaml.safe_load(fm_text) or {}
        return {"frontmatter": fm, "body": body}
