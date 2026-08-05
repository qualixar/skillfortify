"""E7: wall-clock cost of a full scan over the benchmark corpus.

Times the operations a user actually invokes, over the whole corpus, through
the same discovery path the CLI uses. Reports the median of several runs after
a warm-up pass, so the figure reflects steady-state cost rather than the first
traversal's cold filesystem cache.

Timings are specific to the host recorded with them.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from skillfortify.core.analyzer.engine import StaticAnalyzer
from skillfortify.parsers.registry import default_registry

#: Discarded before measuring, so the filesystem cache is warm for every run.
WARMUP_RUNS = 1

#: Measured runs, of which the median is reported.
REPEATS = 5


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def _scan_once(corpus_skills: Path) -> tuple[float, int, int]:
    """Discover and analyse the whole corpus once."""
    registry = default_registry()
    analyzer = StaticAnalyzer()
    start = time.perf_counter()
    skills = registry.discover(corpus_skills)
    results = [analyzer.analyze(skill) for skill in skills]
    elapsed = time.perf_counter() - start
    return elapsed, len(skills), sum(len(r.findings) for r in results)


def run(corpus_root: Path) -> dict[str, Any]:
    """Measure end-to-end scan cost over the corpus."""
    corpus_skills = corpus_root / "skills"

    for _ in range(WARMUP_RUNS):
        _scan_once(corpus_skills)

    samples = []
    discovered = findings = 0
    for _ in range(REPEATS):
        elapsed, discovered, findings = _scan_once(corpus_skills)
        samples.append(elapsed)

    median = _median(samples)
    return {
        "experiment": "E7",
        "description": "End-to-end scan performance over the benchmark corpus",
        "status": "measured",
        "warmup_runs": WARMUP_RUNS,
        "repeats": REPEATS,
        "skills_discovered": discovered,
        "findings_produced": findings,
        "scan": {
            "median_seconds": round(median, 4),
            "min_seconds": round(min(samples), 4),
            "max_seconds": round(max(samples), 4),
            "per_skill_ms": round(median / discovered * 1000, 4) if discovered else None,
        },
        "note": (
            "Discovery and analysis over a single scan root, the path the CLI "
            "takes. Timings are specific to the host recorded with this run."
        ),
    }
