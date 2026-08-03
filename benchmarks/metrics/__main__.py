"""Score a scanner against the corpus and write the results artefacts.

Usage::

    PYTHONHASHSEED=0 python -m benchmarks.metrics \
        --corpus benchmarks --output benchmarks/results

Writes ``specimen-results.json`` (one record per specimen: label, verdict,
finding count, highest severity) and ``summary.json`` (the aggregates every
published table is computed from). Publishing both is what makes a reported
number checkable without rerunning the scan.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from skillfortify.core.analyzer.models import Severity

from .evaluate import write_report
from .leakage import find_leaks, format_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks.metrics")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("benchmarks"),
        help="corpus root holding manifest.json and skills/",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/results"),
        help="directory to write the results artefacts into",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=[s.name.lower() for s in Severity],
        default="medium",
        help="lowest severity that counts as a detection",
    )
    parser.add_argument(
        "--skip-leakage-check",
        action="store_true",
        help="score even if a structural feature predicts the label",
    )
    args = parser.parse_args(argv)

    if not args.skip_leakage_check:
        leaks = find_leaks(args.corpus / "skills")
        if leaks:
            print(format_report(leaks), file=sys.stderr)
            print(
                "\nRefusing to score: the label is recoverable from specimen "
                "shape alone, so any metric would describe the corpus rather "
                "than the scanner. Pass --skip-leakage-check to override.",
                file=sys.stderr,
            )
            return 2

    threshold = Severity[args.severity_threshold.upper()]
    summary = write_report(args.corpus, args.output, threshold=threshold)

    counts = summary["confusion"]
    print(
        f"specimens={summary['specimens']} "
        f"TP={counts['TP']} FP={counts['FP']} "
        f"TN={counts['TN']} FN={counts['FN']}"
    )
    print(
        f"precision={summary['precision']:.4f} "
        f"recall={summary['recall']:.4f} "
        f"f1={summary['f1']:.4f}"
    )
    print(f"wrote {args.output}/specimen-results.json and summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
