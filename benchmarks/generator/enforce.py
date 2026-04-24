"""Table 11 distribution enforcement (LLD-01 §6.12 + §7.11)."""

from __future__ import annotations

from typing import Sequence

from .config import FORMATS, TABLE_11_DISTRIBUTION
from .exceptions import DistributionMismatchError


def _sorted_attack_types() -> list[str]:
    """Return A1..A13 sorted numerically (not lexically)."""
    return [f"A{i}" for i in range(1, 14)]


def enforce_table_11(entries: Sequence) -> None:
    """Raise DistributionMismatchError if per-(format, atype|benign) counts mismatch.

    Iteration order: FORMATS × (A1..A13 numeric + "benign"). Extra buckets not
    present in TABLE_11_DISTRIBUTION are also a failure.
    """
    observed: dict[tuple[str, str], int] = {}
    for entry in entries:
        key = (
            entry.format,
            entry.attack_type if entry.is_malicious else "benign",
        )
        observed[key] = observed.get(key, 0) + 1

    # Check every canonical bucket.
    for fmt in FORMATS:
        for atype in _sorted_attack_types() + ["benign"]:
            key = (fmt, atype)
            expected = TABLE_11_DISTRIBUTION[key]
            got = observed.get(key, 0)
            if got != expected:
                raise DistributionMismatchError(
                    key=key, expected=expected, observed=got,
                )

    # Reject extra buckets not in canonical table.
    for key, count in observed.items():
        if key not in TABLE_11_DISTRIBUTION:
            raise DistributionMismatchError(
                key=key, expected=0, observed=count,
                message=f"unexpected bucket: {key}",
            )
