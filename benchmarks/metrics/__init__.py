"""benchmarks.metrics -- Statistical aggregation engine (LLD-07).

Re-exports Wilson CI, compute_metrics, BenchmarkMetrics, and report generator.
"""

from .compute import (
    AttackTypeMetrics,
    BenchmarkMetrics,
    FormatMetrics,
    compute_metrics,
)
from .report import generate_results_md
from .wilson import wilson_ci, wilson_ci_family

__all__ = [
    "wilson_ci",
    "wilson_ci_family",
    "BenchmarkMetrics",
    "FormatMetrics",
    "AttackTypeMetrics",
    "compute_metrics",
    "generate_results_md",
]
