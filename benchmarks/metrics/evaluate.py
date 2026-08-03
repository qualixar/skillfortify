"""Score SkillFortify against the corpus, one specimen at a time.

Each specimen directory is a self-contained installation root, so it is
scanned on its own and yields exactly one prediction. That keeps the mapping
from label to prediction one-to-one: totals cannot disagree with the per-type
breakdown, because both are derived from the same per-specimen records rather
than reconciled after the fact.

The per-specimen records are written out alongside the summary, so every
number in the published tables can be recomputed from the artefact without
rerunning a scan.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

from skillfortify.core.analyzer.engine import StaticAnalyzer
from skillfortify.core.analyzer.models import Severity
from skillfortify.parsers.registry import default_registry

from .wilson import wilson_ci

#: A specimen counts as detected when it carries a finding at least this
#: severe. Stated here rather than left to a caller's default so that the
#: threshold behind a published number is never ambiguous.
DEFAULT_THRESHOLD = Severity.MEDIUM


def _safe_div(numerator: float, denominator: float) -> float:
    """Divide, treating an empty denominator as zero rather than an error."""
    return numerator / denominator if denominator else 0.0


def precision_score(tp: int, fp: int) -> float:
    return _safe_div(tp, tp + fp)


def recall_score(tp: int, fn: int) -> float:
    return _safe_div(tp, tp + fn)


def f1_score(tp: int, fp: int, fn: int) -> float:
    precision = precision_score(tp, fp)
    recall = recall_score(tp, fn)
    return _safe_div(2 * precision * recall, precision + recall)


@dataclass(frozen=True)
class SpecimenResult:
    """One specimen, its label, and what the scanner said about it."""

    skill_id: str
    format: str
    attack_type: str
    is_malicious: bool
    detected: bool
    skills_found: int
    max_severity: str | None
    finding_count: int

    @property
    def outcome(self) -> str:
        if self.is_malicious:
            return "TP" if self.detected else "FN"
        return "FP" if self.detected else "TN"


def evaluate_specimen(
    specimen_root: Path,
    *,
    threshold: Severity = DEFAULT_THRESHOLD,
) -> tuple[bool, int, Severity | None, int]:
    """Scan one specimen root. Returns (detected, skills, max severity, findings)."""
    skills = default_registry().discover(specimen_root)
    if not skills:
        return False, 0, None, 0

    analyzer = StaticAnalyzer()
    severities: list[Severity] = []
    findings = 0
    for skill in skills:
        result = analyzer.analyze(skill)
        for finding in result.findings:
            findings += 1
            severities.append(finding.severity)

    worst = max(severities) if severities else None
    detected = worst is not None and worst >= threshold
    return detected, len(skills), worst, findings


def evaluate_corpus(
    corpus_root: Path,
    *,
    threshold: Severity = DEFAULT_THRESHOLD,
) -> list[SpecimenResult]:
    """Scan every specimen listed in the corpus manifest."""
    manifest = json.loads((corpus_root / "manifest.json").read_text())
    seen: dict[str, SpecimenResult] = {}

    for entry in manifest["entries"]:
        specimen_root = (corpus_root / entry["path"]).parent
        # Walk up to the specimen root: the manifest points at the skill file,
        # which sits below the installation directory it is loaded from.
        while specimen_root.name != entry["skill_id"]:
            if specimen_root == corpus_root or specimen_root.parent == specimen_root:
                raise ValueError(f"no specimen root above {entry['path']}")
            specimen_root = specimen_root.parent

        if entry["skill_id"] in seen:
            continue

        detected, found, worst, findings = evaluate_specimen(
            specimen_root, threshold=threshold
        )
        seen[entry["skill_id"]] = SpecimenResult(
            skill_id=entry["skill_id"],
            format=entry["format"],
            attack_type=entry["attack_type"] if entry["is_malicious"] else "benign",
            is_malicious=entry["is_malicious"],
            detected=detected,
            skills_found=found,
            max_severity=worst.name if worst is not None else None,
            finding_count=findings,
        )
    return list(seen.values())


def confusion(results: Iterable[SpecimenResult]) -> dict[str, int]:
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for result in results:
        counts[result.outcome] += 1
    return counts


def summarize(results: Sequence[SpecimenResult]) -> dict:
    """Compute headline metrics plus per-format and per-type breakdowns."""
    counts = confusion(results)
    tp, fp, fn = counts["TP"], counts["FP"], counts["FN"]

    malicious = [r for r in results if r.is_malicious]
    benign = [r for r in results if not r.is_malicious]

    summary = {
        "specimens": len(results),
        "confusion": counts,
        "precision": precision_score(tp, fp),
        "recall": recall_score(tp, fn),
        "f1": f1_score(tp, fp, fn),
        "recall_ci": wilson_ci(tp, len(malicious)) if malicious else None,
        "precision_ci": wilson_ci(tp, tp + fp) if (tp + fp) else None,
        "specificity_ci": wilson_ci(counts["TN"], len(benign)) if benign else None,
        "by_format": {},
        "by_attack_type": {},
    }

    for fmt in sorted({r.format for r in results}):
        subset = [r for r in results if r.format == fmt]
        sub_counts = confusion(subset)
        summary["by_format"][fmt] = _breakdown(sub_counts, subset)

    for attack in sorted(
        {r.attack_type for r in results if r.is_malicious},
        key=lambda a: int(a[1:]),
    ):
        subset = [r for r in results if r.attack_type == attack]
        detected = sum(1 for r in subset if r.detected)
        summary["by_attack_type"][attack] = {
            "total": len(subset),
            "detected": detected,
            "missed": len(subset) - detected,
            "recall": detected / len(subset) if subset else 0.0,
            "recall_ci": wilson_ci(detected, len(subset)),
        }

    return summary


def _breakdown(counts: dict[str, int], subset: Sequence[SpecimenResult]) -> dict:
    tp, fp, fn = counts["TP"], counts["FP"], counts["FN"]
    malicious = sum(1 for r in subset if r.is_malicious)
    return {
        "confusion": counts,
        "precision": precision_score(tp, fp),
        "recall": recall_score(tp, fn),
        "f1": f1_score(tp, fp, fn),
        "recall_ci": wilson_ci(tp, malicious) if malicious else None,
    }


def write_report(
    corpus_root: Path,
    output_dir: Path,
    *,
    threshold: Severity = DEFAULT_THRESHOLD,
) -> dict:
    """Evaluate the corpus and write both the per-specimen and summary files."""
    from skillfortify import __version__ as scanner_version

    results = evaluate_corpus(corpus_root, threshold=threshold)
    summary = summarize(results)
    summary["severity_threshold"] = threshold.name
    # Recorded so a results file states which scanner produced it. A table
    # whose subject is implicit is one release away from being wrong.
    summary["scanner_version"] = scanner_version

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "specimen-results.json").write_text(
        json.dumps([asdict(r) for r in sorted(results, key=lambda r: r.skill_id)], indent=2)
        + "\n"
    )
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
