"""Detect structural features that give a specimen's label away.

A generated corpus is produced by two code paths, one per class. Anything the
two paths do differently -- a key only one of them emits, a directory only one
of them creates, a marker one of them writes twice -- becomes a feature that
predicts the label without reading the content. A scanner scored against such
a corpus can post a high number while detecting nothing, and the metric is
worthless in a way that is invisible from the metric itself.

This module enumerates *structural* features only (frontmatter and JSON keys,
path components, section headings, sentinel occurrence counts) and reports any
whose presence is near-perfectly correlated with the label. Content words are
deliberately excluded: a malicious specimen is *supposed* to contain ``curl``
and an evil hostname, and flagging that would be noise. The question this
answers is narrower and answerable: can the label be recovered from the shape
of the file alone?

Used by ``tests/benchmarks/test_corpus_leakage.py`` as a release gate.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

import yaml

#: A feature must appear this often before its purity is worth reporting.
MIN_SUPPORT = 8

#: Fraction of a feature's occurrences that may share one label before the
#: feature counts as label-revealing. 1.0 means "only perfect separators fail".
MAX_PURITY = 0.95


@dataclass(frozen=True)
class LeakReport:
    """One structural feature that predicts the label."""

    feature: str
    malicious: int
    benign: int

    @property
    def support(self) -> int:
        return self.malicious + self.benign

    @property
    def purity(self) -> float:
        return max(self.malicious, self.benign) / self.support

    @property
    def predicts(self) -> str:
        return "malicious" if self.malicious > self.benign else "benign"

    def __str__(self) -> str:
        return (
            f"{self.feature}: {self.support} occurrences, "
            f"{self.purity:.0%} {self.predicts} "
            f"(mal={self.malicious}, ben={self.benign})"
        )


def _frontmatter_and_body(text: str) -> tuple[dict, str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}, text
    try:
        front = yaml.safe_load(text[4:end]) or {}
    except yaml.YAMLError:
        front = {}
    return (front if isinstance(front, dict) else {}), text[end + 5 :]


#: Fields whose *values* come from a closed vocabulary and are therefore part
#: of a specimen's shape rather than its content. A value drawn from one of
#: these gives the label away exactly as a key would, so both are enumerated.
_ENUMERATED_FIELDS = frozenset({"allowed-tools", "author", "version"})

#: Longest value still treated as an enumeration member rather than free text.
_MAX_ENUM_VALUE_LEN = 40


def _flatten_keys(obj: object, prefix: str = "") -> Iterator[str]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield path
            yield from _flatten_keys(value, path)
    elif isinstance(obj, list):
        for item in obj:
            yield from _flatten_keys(item, prefix)


def _enumerated_values(front: dict) -> Iterator[str]:
    """Yield ``field=value`` for every closed-vocabulary field present."""
    for field in sorted(_ENUMERATED_FIELDS):
        value = front.get(field)
        if value is None:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            text = str(item)
            if len(text) <= _MAX_ENUM_VALUE_LEN:
                yield f"value:{field}={text}"


def specimen_features(root: Path) -> set[str]:
    """Return the structural features of one specimen directory."""
    features: set[str] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        for part in relative.parts[:-1]:
            features.add(f"path:{part}")
        features.add(f"file:{relative.name}")

        text = path.read_text(encoding="utf-8", errors="replace")
        features.add(f"sentinel_count:{text.count('SKILLFORTIFYBENCH:INERT')}")

        if path.suffix == ".json":
            try:
                features.update(f"key:{k}" for k in _flatten_keys(json.loads(text)))
            except json.JSONDecodeError:
                features.add("key:<unparseable>")
            continue

        front, body = _frontmatter_and_body(text)
        features.update(f"key:{k}" for k in _flatten_keys(front))
        features.update(_enumerated_values(front))
        headings = [
            line.split(" ", 1)[0]
            for line in body.splitlines()
            if line.startswith("#")
        ]
        features.update(f"heading_level:{h}" for h in headings)
        features.add(f"has_prose:{_has_prose(body)}")
        features.add(f"fence_count:{body.count('```') // 2}")
    return features


def _has_prose(body: str) -> bool:
    """True if the body has a paragraph that is not a heading or a fence."""
    in_fence = False
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or not stripped:
            continue
        if stripped.startswith(("#", "<!--", "-")):
            continue
        return True
    return False


def iter_specimens(skills_root: Path) -> Iterator[tuple[Path, bool]]:
    """Yield ``(specimen_root, is_malicious)`` for every specimen."""
    for label_dir in sorted(skills_root.glob("*/*")):
        if not label_dir.is_dir() or label_dir.name not in {"malicious", "benign"}:
            continue
        is_malicious = label_dir.name == "malicious"
        for specimen in sorted(label_dir.iterdir()):
            if specimen.is_dir():
                yield specimen, is_malicious


def find_leaks(
    skills_root: Path,
    *,
    min_support: int = MIN_SUPPORT,
    max_purity: float = MAX_PURITY,
) -> list[LeakReport]:
    """Return every structural feature that predicts the label too well."""
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for specimen, is_malicious in iter_specimens(skills_root):
        for feature in specimen_features(specimen):
            counts[feature][0 if is_malicious else 1] += 1

    leaks = [
        LeakReport(feature=feature, malicious=mal, benign=ben)
        for feature, (mal, ben) in counts.items()
        if mal + ben >= min_support
    ]
    return sorted(
        (leak for leak in leaks if leak.purity > max_purity),
        key=lambda leak: (-leak.purity, -leak.support),
    )


def format_report(leaks: Iterable[LeakReport]) -> str:
    leaks = list(leaks)
    if not leaks:
        return "No structural feature predicts the label above threshold."
    lines = [f"{len(leaks)} label-revealing structural feature(s):"]
    lines.extend(f"  {leak}" for leak in leaks)
    return "\n".join(lines)
