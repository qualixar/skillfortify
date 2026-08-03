"""RESULTS.md generator (LLD-07 S11).

Produces markdown tables reproducing paper Tables 4-7.
"""

from __future__ import annotations

from .compute import BenchmarkMetrics

__all__ = ["generate_results_md"]


def _fmt_pct(value: float, decimals: int = 4) -> str:
    """Format a rate as a percentage string."""
    return f"{value * 100:.{decimals}f}%"


def _fmt_ci(ci: tuple[float, float], decimals: int = 2) -> str:
    """Format a Wilson CI as a percentage range."""
    return f"[{ci[0] * 100:.{decimals}f}%, {ci[1] * 100:.{decimals}f}%]"


def generate_results_md(metrics: BenchmarkMetrics) -> str:
    """Generate a RESULTS.md markdown string with Tables 4-7 reproduction.

    Parameters
    ----------
    metrics:
        Computed BenchmarkMetrics from compute_metrics().

    Returns
    -------
    Markdown string suitable for writing to RESULTS.md.
    """
    lines: list[str] = []

    lines.append("# SkillFortify Benchmark Results")
    lines.append("")
    lines.append(
        "Deterministic execution of the benchmark specification "
        "in Appendix B of arXiv:2603.00195."
    )
    lines.append("")

    # Table 4: Overall metrics.
    lines.append("## Table 4: Overall Precision / Recall / F1")
    lines.append("")
    lines.append(
        "| Metric | Value | Wilson 95% CI |"
    )
    lines.append("| --- | --- | --- |")
    lines.append(
        f"| Precision | {_fmt_pct(metrics.precision)} "
        f"| {_fmt_ci(metrics.precision_ci)} |"
    )
    lines.append(
        f"| Recall | {_fmt_pct(metrics.recall)} "
        f"| {_fmt_ci(metrics.recall_ci)} |"
    )
    lines.append(
        f"| F1 | {_fmt_pct(metrics.f1)} | - |"
    )
    lines.append("")
    lines.append(
        f"Total skills: {metrics.total_skills} "
        f"(malicious: {metrics.total_malicious}, "
        f"benign: {metrics.total_benign})"
    )
    lines.append(
        f"TP: {metrics.true_positives}, FP: {metrics.false_positives}, "
        f"FN: {metrics.false_negatives}, TN: {metrics.true_negatives}"
    )
    lines.append("")

    # Table 5: Per-format recall.
    lines.append("## Table 5: Per-Format Recall Breakdown")
    lines.append("")
    lines.append(
        "| Format | Malicious | Detected | Missed | FP | "
        "Recall | Wilson 95% CI |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for fmt_key in sorted(metrics.per_format.keys()):
        fm = metrics.per_format[fmt_key]
        lines.append(
            f"| {fm.format} | {fm.malicious} | {fm.detected} | "
            f"{fm.missed} | {fm.false_positives} | "
            f"{_fmt_pct(fm.recall)} | {_fmt_ci(fm.recall_ci)} |"
        )
    lines.append("")

    # Table 6: Per-attack-type recall.
    lines.append("## Table 6: Per-Attack-Type Recall")
    lines.append("")
    lines.append(
        "| Attack Type | Total | Detected | Missed | "
        "Recall | Wilson 95% CI |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for atype_key in sorted(metrics.per_attack_type.keys()):
        am = metrics.per_attack_type[atype_key]
        lines.append(
            f"| {am.attack_type} | {am.total} | {am.detected} | "
            f"{am.missed} | {_fmt_pct(am.recall)} | "
            f"{_fmt_ci(am.recall_ci)} |"
        )
    lines.append("")

    # Headline metrics for this run.
    #
    # An earlier version of this table compared every run against a hardcoded
    # published recall and reported whether that figure fell inside the run's
    # confidence interval. With a fixed target on the page, a run that differs
    # from it reads as agreement whenever the interval is wide enough, which
    # is a property of the sample size rather than of the scanner. The run
    # stands on its own numbers instead.
    lines.append("## Table 7: Headline Metrics")
    lines.append("")
    lines.append("| Metric | Value | Wilson 95% CI |")
    lines.append("| --- | --- | --- |")
    lines.append(
        f"| Precision | {_fmt_pct(metrics.precision)} | "
        f"{_fmt_ci(metrics.precision_ci)} |"
    )
    lines.append(
        f"| Recall | {_fmt_pct(metrics.recall)} | {_fmt_ci(metrics.recall_ci)} |"
    )
    lines.append(f"| F1 | {_fmt_pct(metrics.f1)} | — |")
    lines.append("")

    lines.append(
        "*Wilson intervals are computed on the underlying proportion. F1 is a "
        "point estimate: it is not a binomial proportion, so a Wilson interval "
        "on it would not mean anything.*"
    )
    lines.append("")

    return "\n".join(lines)
