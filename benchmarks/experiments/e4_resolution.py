"""E4: how does SAT-based dependency resolution scale with skill count?

Builds dependency graphs of increasing size from a fixed seed, so the same
graphs are generated on every machine, and times complete resolution on each.
Reports the median of several runs alongside the host, so one scheduling
hiccup cannot become a published number.

The resolver needs ``python-sat``, an optional extra. When it is absent this
records that rather than reporting a number it did not measure.
"""

from __future__ import annotations

import random
import time
from typing import Any

from skillfortify.core.dependency.constraints import VersionConstraint
from skillfortify.core.dependency.graph import (
    AgentDependencyGraph,
    SkillDependency,
    SkillNode,
)
from skillfortify.core.dependency.resolver import DependencyResolver

#: Skill counts to measure, spanning a small project to an order of magnitude
#: beyond the largest enterprise deployments we are aware of.
SKILL_COUNTS = (10, 50, 100, 200, 500, 1000)

#: Repeats per size, of which the median is reported.
REPEATS = 5

#: Fixed so the generated graphs are identical on every machine and run.
SEED = 42

#: Upper bound on dependency edges per skill.
MAX_DEPS_PER_SKILL = 3

_CONSTRAINT = VersionConstraint(raw=">=1.0.0")


def build_graph(count: int, seed: int = SEED) -> tuple[AgentDependencyGraph, list[str]]:
    """Build a deterministic acyclic dependency graph of ``count`` skills.

    Each skill may depend on skills earlier in the ordering, which keeps the
    graph acyclic by construction so the experiment measures resolution rather
    than cycle rejection.
    """
    rng = random.Random(seed)
    graph = AgentDependencyGraph()
    names = [f"skill-{i:04d}" for i in range(count)]
    for index, name in enumerate(names):
        edge_count = min(index, rng.randint(0, MAX_DEPS_PER_SKILL))
        dependencies = [
            SkillDependency(skill_name=names[j], constraint=_CONSTRAINT)
            for j in rng.sample(range(index), edge_count)
        ]
        graph.add_skill(
            SkillNode(name=name, version="1.0.0", dependencies=dependencies)
        )
    return graph, names


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def run() -> dict[str, Any]:
    """Measure resolution wall-clock time across increasing skill counts."""
    try:
        import pysat  # noqa: F401
    except ImportError:
        return {
            "experiment": "E4",
            "description": "SAT-based dependency resolution scalability",
            "status": "skipped",
            "reason": (
                "python-sat is not installed. Install the optional extra with "
                "`pip install 'skillfortify[sat]'` to run this experiment."
            ),
            "measurements": [],
        }

    measurements = []
    for count in SKILL_COUNTS:
        graph, names = build_graph(count)
        requirements = {name: _CONSTRAINT for name in names}
        samples = []
        success = None
        for _ in range(REPEATS):
            start = time.perf_counter()
            resolution = DependencyResolver(graph, requirements=requirements).resolve()
            samples.append(time.perf_counter() - start)
            success = resolution.success
        median = _median(samples)
        measurements.append(
            {
                "skills": count,
                "median_seconds": round(median, 6),
                "min_seconds": round(min(samples), 6),
                "max_seconds": round(max(samples), 6),
                "per_skill_ms": round(median / count * 1000, 4),
                "resolved": success,
            }
        )

    return {
        "experiment": "E4",
        "description": "SAT-based dependency resolution scalability",
        "status": "measured",
        "seed": SEED,
        "repeats": REPEATS,
        "max_dependencies_per_skill": MAX_DEPS_PER_SKILL,
        "solver": "Glucose3 (CDCL) via python-sat",
        "measurements": measurements,
    }
