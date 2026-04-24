"""Exception taxonomy for benchmarks.generator.

Per LLD-01 §9. All generator-raised exceptions inherit from GeneratorError,
which itself inherits from Exception (not ValueError, to keep a clear namespace).
"""

from __future__ import annotations

from typing import Sequence


class GeneratorError(Exception):
    """Base class for all benchmarks.generator errors."""


class DistributionMismatchError(GeneratorError):
    """Raised by enforce_table_11 on any (format, attack_type) mismatch."""

    def __init__(
        self,
        *,
        key: tuple[str, str],
        expected: int,
        observed: int,
        message: str | None = None,
    ) -> None:
        self.key = key
        self.expected = expected
        self.observed = observed
        msg = message or (
            f"Table 11 mismatch at {key}: expected {expected}, got {observed}"
        )
        super().__init__(msg)


class RegistryIncompleteError(GeneratorError):
    """Raised in __init__ if A1..A13 or benign categories are missing."""

    def __init__(
        self,
        *,
        missing: tuple[str, ...] = (),
        kind: str = "attack",
        message: str | None = None,
    ) -> None:
        self.missing = tuple(missing)
        self.kind = kind
        super().__init__(
            message or f"registry incomplete ({kind}); missing={self.missing}"
        )


class NonDeterministicSeedLeakError(GeneratorError):
    """Raised by guard_global_random on any stub invocation."""


class UnsafeOutputRootError(GeneratorError):
    """Raised by _assert_safe_output_root on any rejection."""

    def __init__(self, path, rule: str, message: str | None = None) -> None:
        self.path = path
        self.rule = rule
        # Always prefix the rule name so tests can match=<rule> reliably.
        detail = f" ({message})" if message else ""
        super().__init__(f"{rule}: {path}{detail}")


class ParserRoundtripError(GeneratorError):
    """Raised when dialect.parse or skillfortify.parsers.parse_file fails."""


class ManifestIntegrityError(GeneratorError):
    """Raised on manifest structural or hash mismatch."""


class ForbiddenWordError(GeneratorError):
    """Raised when forbidden words appear in any emitted artifact."""


class PreflightViolationError(GeneratorError):
    """Raised when ast_scan_package returns a non-empty violation list."""

    def __init__(self, violations: Sequence[object]) -> None:
        self.violations = tuple(violations)
        super().__init__(f"{len(self.violations)} preflight violation(s)")


class MultiProcessError(GeneratorError):
    """Raised when a multi-thread or multi-process environment is detected."""


class NonDeterministicEnvironmentError(GeneratorError):
    """Raised when PYTHONHASHSEED != '0' or equivalent nondeterminism source."""
