"""T6 Metrics Engine tests (LLD-07 Stage 6).

8 tests covering Wilson CI, compute_metrics, per-format/per-attack-type
breakdown, and RESULTS.md generation.
"""

from __future__ import annotations

import pytest

from benchmarks.metrics.compute import compute_metrics
from benchmarks.metrics.report import generate_results_md
from benchmarks.metrics.wilson import wilson_ci


# -----------------------------------------------------------------------
# Wilson CI tests
# -----------------------------------------------------------------------


class TestWilsonCI:
    """Wilson score confidence interval validation."""

    def test_wilson_ci_canonical(self) -> None:
        """Wilson(254, 270, z=1.96) ~ [0.9059, 0.9632] within 1e-3."""
        lo, hi = wilson_ci(254, 270, z=1.96)
        assert abs(lo - 0.9059) < 1e-3, f"lower={lo}"
        assert abs(hi - 0.9632) < 1e-3, f"upper={hi}"
        # Paper point estimate 0.9407 must fall inside.
        assert lo <= 0.9407 <= hi

    def test_wilson_ci_perfect(self) -> None:
        """Wilson(10, 10) -> lower > 0.65 (never zero-width at k=n)."""
        lo, hi = wilson_ci(10, 10, z=1.96)
        assert lo > 0.65
        assert hi <= 1.0

    def test_wilson_ci_zero(self) -> None:
        """Wilson(0, 10) -> (0.0, ~0.31) -- lower bound is zero."""
        lo, hi = wilson_ci(0, 10, z=1.96)
        assert lo == 0.0
        assert 0.25 < hi < 0.35

    def test_wilson_ci_total_zero(self) -> None:
        """Wilson(0, 0) -> (0.0, 0.0)."""
        lo, hi = wilson_ci(0, 0)
        assert lo == 0.0
        assert hi == 0.0


# -----------------------------------------------------------------------
# compute_metrics tests
# -----------------------------------------------------------------------


def _make_result(
    skill_id: str,
    fmt: str,
    is_malicious: bool,
    detected: bool,
    attack_type: str | None = None,
) -> dict:
    """Helper to build a per-skill result dict."""
    return {
        "skill_id": skill_id,
        "format": fmt,
        "is_malicious": is_malicious,
        "attack_type": attack_type,
        "detected": detected,
    }


class TestComputeMetrics:
    """BenchmarkMetrics computation validation."""

    def test_compute_metrics_basic(self) -> None:
        """270 TP, 0 FP, 270 TN -> precision=1.0, recall=1.0."""
        results: list[dict] = []
        for i in range(270):
            results.append(
                _make_result(f"mal_{i}", "json", True, True, "A1")
            )
        for i in range(270):
            results.append(
                _make_result(f"ben_{i}", "json", False, False)
            )

        m = compute_metrics(results)
        assert m.total_skills == 540
        assert m.total_malicious == 270
        assert m.total_benign == 270
        assert m.true_positives == 270
        assert m.false_positives == 0
        assert m.false_negatives == 0
        assert m.true_negatives == 270
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1 == 1.0

    def test_compute_metrics_with_misses(self) -> None:
        """254 TP, 16 FN, 0 FP -> recall ~ 0.9407."""
        results: list[dict] = []
        # 254 detected malicious.
        for i in range(254):
            results.append(
                _make_result(f"mal_{i}", "yaml", True, True, "A1")
            )
        # 16 missed malicious.
        for i in range(16):
            results.append(
                _make_result(f"mal_miss_{i}", "yaml", True, False, "A2")
            )
        # 270 benign, none flagged.
        for i in range(270):
            results.append(
                _make_result(f"ben_{i}", "yaml", False, False)
            )

        m = compute_metrics(results)
        assert m.true_positives == 254
        assert m.false_negatives == 16
        assert m.false_positives == 0
        assert abs(m.recall - 254 / 270) < 1e-6
        assert m.precision == 1.0
        # Recall CI should contain the paper point estimate.
        assert m.recall_ci[0] <= 0.9407 <= m.recall_ci[1]

    def test_per_format_breakdown(self) -> None:
        """3 format entries, each with correct counts."""
        results: list[dict] = []
        formats = ["json", "yaml", "toml"]
        for fmt in formats:
            # 10 malicious detected per format.
            for i in range(10):
                results.append(
                    _make_result(f"mal_{fmt}_{i}", fmt, True, True, "A1")
                )
            # 2 malicious missed per format.
            for i in range(2):
                results.append(
                    _make_result(f"mal_miss_{fmt}_{i}", fmt, True, False, "A3")
                )
            # 5 benign per format.
            for i in range(5):
                results.append(
                    _make_result(f"ben_{fmt}_{i}", fmt, False, False)
                )

        m = compute_metrics(results)
        assert len(m.per_format) == 3

        for fmt in formats:
            fm = m.per_format[fmt]
            assert fm.malicious == 12
            assert fm.detected == 10
            assert fm.missed == 2
            assert fm.benign == 5
            assert fm.false_positives == 0
            assert abs(fm.recall - 10 / 12) < 1e-6


# -----------------------------------------------------------------------
# RESULTS.md generation test
# -----------------------------------------------------------------------


class TestResultsMd:
    """RESULTS.md output validation."""

    def test_results_md_contains_tables(self) -> None:
        """Output contains 'Precision', 'Recall', 'Wilson'."""
        results: list[dict] = []
        for i in range(50):
            results.append(
                _make_result(f"mal_{i}", "json", True, True, "A1")
            )
        for i in range(50):
            results.append(
                _make_result(f"ben_{i}", "json", False, False)
            )

        m = compute_metrics(results)
        md = generate_results_md(m)

        assert "Precision" in md
        assert "Recall" in md
        assert "Wilson" in md
        assert "Table 4" in md
        assert "Table 5" in md
        assert "Table 6" in md
        assert "Table 7" in md
