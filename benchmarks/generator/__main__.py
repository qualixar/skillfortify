"""CLI entry for benchmarks.generator (LLD-01 §6.14).

This module is the ONLY permitted os.environ reader (F-C-37). It forwards the
observed PYTHONHASHSEED value to BenchmarkGenerator via a constructor arg.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks.generator")
    parser.add_argument("--output", type=Path, required=False)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)

    if args.version:
        from . import __version__ as _v

        print(_v)
        return 0

    # SINGLE permitted os.environ read point.
    pythonhashseed_observed = os.environ.get("PYTHONHASHSEED", "UNSET")
    if pythonhashseed_observed != "0":
        print(
            'ERROR: PYTHONHASHSEED must be set to "0" for deterministic generation',
            file=sys.stderr,
        )
        return 2

    if args.output is None:
        print("ERROR: --output PATH is required", file=sys.stderr)
        return 2

    # Late import so AST preflight of the generator package runs at construction.
    from .benign import BENIGN_REGISTRY
    from .core import BenchmarkGenerator
    from .exceptions import GeneratorError
    from .seeds import PATTERN_REGISTRY

    attack_type_to_class = {
        aid: pat.parent_class for aid, pat in PATTERN_REGISTRY.items()
    }

    try:
        gen = BenchmarkGenerator(
            output_root=args.output,
            seed=args.seed,
            attack_registry=PATTERN_REGISTRY,
            benign_registry=BENIGN_REGISTRY,
            attack_type_to_class=attack_type_to_class,
            pythonhashseed_observed=pythonhashseed_observed,
            parser_roundtrip=False,
            dry_run=args.dry_run,
            verify_only=args.verify_only,
        )
        report = gen.run()
    except GeneratorError as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"total_skills={report.total_skills}")
    print(f"manifest_content_sha256={report.manifest_content_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
