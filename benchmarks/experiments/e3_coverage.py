"""E3: what does information-flow detection add over pattern matching alone?

Measures the detection partition directly: how many malicious specimens the
pattern catalogue finds on its own, how many the information-flow rule finds,
and how many are found only because the two are combined.

A specimen counts as detected when its worst finding meets the severity
threshold, the same rule ``benchmarks.metrics`` applies, so the two
experiments cannot disagree about which specimens were detected.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from benchmarks.metrics.evaluate import DEFAULT_THRESHOLD
from skillfortify.core.analyzer.engine import StaticAnalyzer
from skillfortify.core.analyzer.models import Severity
from skillfortify.parsers.registry import default_registry

#: Findings produced by the cross-signal information-flow rule.
INFO_FLOW = "info_flow"


def _malicious_specimens(corpus_root: Path) -> list[Path]:
    """Return every malicious specimen directory, in stable order."""
    skills_root = corpus_root / "skills"
    specimens: list[Path] = []
    for fmt_dir in sorted(p for p in skills_root.iterdir() if p.is_dir()):
        malicious = fmt_dir / "malicious"
        if malicious.is_dir():
            specimens.extend(sorted(p for p in malicious.iterdir() if p.is_dir()))
    return specimens


def _detected(findings, threshold: Severity, *, exclude_info_flow: bool) -> bool:
    """Whether these findings would mark a specimen as detected."""
    considered = [
        f
        for f in findings
        if not (exclude_info_flow and f.finding_type == INFO_FLOW)
    ]
    return any(f.severity >= threshold for f in considered)


def run(corpus_root: Path, threshold: Severity = DEFAULT_THRESHOLD) -> dict[str, Any]:
    """Measure detection coverage with and without the information-flow rule."""
    registry = default_registry()
    analyzer = StaticAnalyzer()

    specimens = _malicious_specimens(corpus_root)
    both = pattern_only = 0
    exclusive: list[str] = []
    info_flow_findings = 0
    info_flow_attack_types: Counter[str] = Counter()

    for specimen in specimens:
        findings = [
            finding
            for skill in registry.discover(specimen)
            for finding in analyzer.analyze(skill).findings
        ]
        for finding in findings:
            if finding.finding_type == INFO_FLOW:
                info_flow_findings += 1
                if finding.attack_type is not None:
                    info_flow_attack_types[finding.attack_type.name] += 1

        with_flow = _detected(findings, threshold, exclude_info_flow=False)
        without_flow = _detected(findings, threshold, exclude_info_flow=True)
        both += with_flow
        pattern_only += without_flow
        if with_flow and not without_flow:
            exclusive.append(specimen.name)

    total = len(specimens)
    return {
        "experiment": "E3",
        "description": "Detection coverage: pattern matching alone vs. with information flow",
        "severity_threshold": threshold.name,
        "malicious_specimens": total,
        "detected_with_info_flow": both,
        "detected_pattern_only": pattern_only,
        "detected_exclusively_by_info_flow": len(exclusive),
        "exclusive_specimen_names": exclusive,
        "not_detected": total - both,
        "added_coverage_fraction": round((both - pattern_only) / total, 6) if total else 0.0,
        "info_flow_findings_total": info_flow_findings,
        "info_flow_attack_types": dict(sorted(info_flow_attack_types.items())),
        "interpretation": (
            "The information-flow rule co-occurs with pattern findings on every "
            "specimen it fires for. It adds no detection that pattern matching "
            "does not already make, so its contribution to coverage is zero."
            if not exclusive
            else "The information-flow rule detects specimens pattern matching misses."
        ),
    }
