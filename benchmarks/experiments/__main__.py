"""Run the E3-E7 experiments and write one JSON document of results.

    PYTHONHASHSEED=0 python -m benchmarks.experiments \
        --corpus benchmarks --output benchmarks/results
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.experiments import e3_coverage, e4_resolution, e5_trust
from benchmarks.experiments import e6_lockfile, e7_endtoend
from benchmarks.experiments.host import host_metadata

OUTPUT_FILENAME = "experiments.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks.experiments")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("benchmarks"),
        help="Benchmark root containing skills/ (default: benchmarks)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/results"),
        help="Directory to write experiments.json into",
    )
    args = parser.parse_args(argv)

    corpus_root: Path = args.corpus
    if not (corpus_root / "skills").is_dir():
        print(f"error: no skills/ under {corpus_root}", file=sys.stderr)
        return 2

    document = {
        "host": host_metadata(),
        "experiments": [
            e3_coverage.run(corpus_root),
            e4_resolution.run(),
            e5_trust.run(),
            e6_lockfile.run(),
            e7_endtoend.run(corpus_root),
        ],
    }

    args.output.mkdir(parents=True, exist_ok=True)
    target = args.output / OUTPUT_FILENAME
    target.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")

    for experiment in document["experiments"]:
        status = experiment.get("status", "measured")
        print(f"{experiment['experiment']}: {status}")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
