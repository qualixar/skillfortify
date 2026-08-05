"""Reproducible harnesses for the evaluation experiments E3-E7.

``benchmarks.metrics`` covers detection accuracy and false positives, scoring
the scanner against the corpus and committing the per-specimen records it
aggregates. This package covers the rest of the evaluation: analysis coverage,
resolver scalability, the trust algebra, lockfile determinism, and end-to-end
timing.

Each experiment writes its inputs, its measured outputs, and the host it ran
on into a single JSON document, so every published figure traces to the run
that produced it and can be re-derived on another machine.

Timing results are hardware-dependent. They carry their host metadata and
should be quoted as measured on a stated machine, not as properties of the
software.
"""

from benchmarks.experiments.host import host_metadata

__all__ = ["host_metadata"]
