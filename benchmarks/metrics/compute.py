"""Precision / Recall / F1 computation with per-format and per-attack-type breakdown.

LLD-07 S5. Consumes per-skill result dicts and produces frozen BenchmarkMetrics.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Sequence

from .wilson import wilson_ci

__all__ = [
    "BenchmarkMetrics",
    "FormatMetrics",
    "AttackTypeMetrics",
    "compute_metrics",
]


@dataclass(frozen=True)
class FormatMetrics:
    """Per-format recall breakdown (LLD-07 Table 5)."""

    format: str
    malicious: int
    benign: int
    detected: int
    missed: int
    false_positives: int
    recall: float
    recall_ci: tuple[float, float]


@dataclass(frozen=True)
class AttackTypeMetrics:
    """Per-attack-type recall breakdown (LLD-07 Table 6)."""

    attack_type: str
    total: int
    detected: int
    missed: int
    recall: float
    recall_ci: tuple[float, float]


@dataclass(frozen=True)
class BenchmarkMetrics:
    """Aggregate benchmark metrics with Wilson 95% CIs (LLD-07 Table 4)."""

    total_skills: int
    total_malicious: int
    total_benign: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1: float
    precision_ci: tuple[float, float]
    recall_ci: tuple[float, float]
    per_format: dict[str, FormatMetrics]
    per_attack_type: dict[str, AttackTypeMetrics]


def _safe_div(numerator: float, denominator: float) -> float:
    """Division with zero-denominator guard. Returns 0.0 when denominator is 0."""
    if denominator == 0:
        return 0.0
    return numerator / denominator


def compute_metrics(results: Sequence[dict]) -> BenchmarkMetrics:
    """Compute benchmark metrics from per-skill result dicts.

    Each dict must contain:
        - skill_id: str
        - format: str
        - is_malicious: bool
        - attack_type: str | None
        - detected: bool

    Returns a frozen BenchmarkMetrics dataclass.
    """
    tp = 0
    fp = 0
    fn = 0
    tn = 0

    # Per-format accumulators.
    fmt_malicious: dict[str, int] = defaultdict(int)
    fmt_benign: dict[str, int] = defaultdict(int)
    fmt_detected: dict[str, int] = defaultdict(int)
    fmt_missed: dict[str, int] = defaultdict(int)
    fmt_fp: dict[str, int] = defaultdict(int)

    # Per-attack-type accumulators.
    atk_total: dict[str, int] = defaultdict(int)
    atk_detected: dict[str, int] = defaultdict(int)
    atk_missed: dict[str, int] = defaultdict(int)

    all_formats: set[str] = set()

    for r in results:
        fmt = r["format"]
        is_mal = r["is_malicious"]
        detected = r["detected"]
        attack_type = r.get("attack_type")

        all_formats.add(fmt)

        if is_mal:
            fmt_malicious[fmt] += 1
            if detected:
                tp += 1
                fmt_detected[fmt] += 1
                if attack_type:
                    atk_detected[attack_type] += 1
            else:
                fn += 1
                fmt_missed[fmt] += 1
                if attack_type:
                    atk_missed[attack_type] += 1
            if attack_type:
                atk_total[attack_type] += 1
        else:
            fmt_benign[fmt] += 1
            if detected:
                fp += 1
                fmt_fp[fmt] += 1
            else:
                tn += 1

    total_malicious = tp + fn
    total_benign = fp + tn
    total_skills = total_malicious + total_benign

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    precision_ci = wilson_ci(tp, tp + fp)
    recall_ci = wilson_ci(tp, tp + fn)

    # Per-format metrics.
    per_format: dict[str, FormatMetrics] = {}
    for fmt in sorted(all_formats):
        mal = fmt_malicious[fmt]
        ben = fmt_benign[fmt]
        det = fmt_detected[fmt]
        mis = fmt_missed[fmt]
        f_fp = fmt_fp[fmt]
        fmt_recall = _safe_div(det, mal)
        fmt_recall_ci = wilson_ci(det, mal)
        per_format[fmt] = FormatMetrics(
            format=fmt,
            malicious=mal,
            benign=ben,
            detected=det,
            missed=mis,
            false_positives=f_fp,
            recall=fmt_recall,
            recall_ci=fmt_recall_ci,
        )

    # Per-attack-type metrics.
    per_attack_type: dict[str, AttackTypeMetrics] = {}
    for atype in sorted(atk_total.keys()):
        total = atk_total[atype]
        det = atk_detected[atype]
        mis = atk_missed[atype]
        a_recall = _safe_div(det, total)
        a_recall_ci = wilson_ci(det, total)
        per_attack_type[atype] = AttackTypeMetrics(
            attack_type=atype,
            total=total,
            detected=det,
            missed=mis,
            recall=a_recall,
            recall_ci=a_recall_ci,
        )

    return BenchmarkMetrics(
        total_skills=total_skills,
        total_malicious=total_malicious,
        total_benign=total_benign,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=precision,
        recall=recall,
        f1=f1,
        precision_ci=precision_ci,
        recall_ci=recall_ci,
        per_format=per_format,
        per_attack_type=per_attack_type,
    )
