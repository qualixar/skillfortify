"""E6: is lockfile generation deterministic?

A lockfile is committed to version control, so repeated generation from
identical inputs must produce identical bytes. Anything else shows up in code
review as churn that hides the dependency changes a reviewer is looking for.

Two properties are measured separately, because they answer different
questions. The resolved content -- which skills at which versions, with which
integrity digests -- must be identical on every run; that is a property of the
resolver. The whole document is additionally byte-identical when
``SOURCE_DATE_EPOCH`` pins the generation timestamp, which is what a build
system needs.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from benchmarks.experiments.e4_resolution import build_graph
from skillfortify.core.dependency.constraints import VersionConstraint
from skillfortify.core.dependency.resolver import DependencyResolver
from skillfortify.core.lockfile.lockfile import Lockfile

#: Configuration sizes to lock, spanning trivial to moderately connected.
CONFIGURATIONS = (3, 5, 8, 12, 16, 20, 25, 32, 40, 50)

_CONSTRAINT = VersionConstraint(raw=">=1.0.0")


def _lock_bytes(count: int, seed: int) -> str | None:
    """Resolve and serialise one configuration, returning its JSON text."""
    graph, names = build_graph(count, seed=seed)
    requirements = {name: _CONSTRAINT for name in names}
    resolution = DependencyResolver(graph, requirements=requirements).resolve()
    if not resolution.success:
        return None
    return Lockfile.from_resolution(resolution).to_json()


def _resolved_content(document: str) -> str:
    """Strip provenance fields that legitimately vary between two runs."""
    data = json.loads(document)
    data.pop("generated_at", None)
    return json.dumps(data, sort_keys=True)


def run() -> dict[str, Any]:
    """Lock each configuration twice and compare the two serialisations."""
    try:
        import pysat  # noqa: F401
    except ImportError:
        return {
            "experiment": "E6",
            "description": "Lockfile determinism",
            "status": "skipped",
            "reason": (
                "python-sat is not installed. Install the optional extra with "
                "`pip install 'skillfortify[sat]'` to run this experiment."
            ),
            "configurations": [],
        }

    previous_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
    try:
        results = []
        content_identical = 0
        bytes_identical = 0
        for index, count in enumerate(CONFIGURATIONS):
            seed = 1000 + index
            first = _lock_bytes(count, seed)
            second = _lock_bytes(count, seed)
            resolved = first is not None and second is not None

            whole = resolved and first == second
            content = resolved and _resolved_content(first) == _resolved_content(second)
            bytes_identical += whole
            content_identical += content

            results.append(
                {
                    "skills": count,
                    "seed": seed,
                    "resolved": resolved,
                    "content_identical": content,
                    "byte_identical_with_pinned_epoch": whole,
                    "sha256": hashlib.sha256(first.encode()).hexdigest()[:16]
                    if first
                    else None,
                }
            )
    finally:
        if previous_epoch is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = previous_epoch

    total = len(CONFIGURATIONS)
    return {
        "experiment": "E6",
        "description": "Lockfile determinism",
        "status": "measured",
        "configurations_tested": total,
        "content_identical": content_identical,
        "content_determinism_fraction": round(content_identical / total, 4),
        "byte_identical_with_pinned_epoch": bytes_identical,
        "byte_determinism_fraction": round(bytes_identical / total, 4),
        "configurations": results,
        "mechanisms": [
            "canonical JSON serialisation with sorted keys",
            "deterministic SAT solving with fixed variable ordering",
            "SHA-256 content hashing of resolved skill artifacts",
        ],
    }
