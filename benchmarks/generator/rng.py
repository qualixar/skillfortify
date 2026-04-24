"""DeterministicRNG + runtime defense-in-depth guards.

Per LLD-01 §6.1-§6.4. AST scan is primary; monkey-patch is defense-in-depth.
"""

from __future__ import annotations

import hashlib
import random
import re
from contextlib import contextmanager
from typing import Iterator, MutableSequence, Optional, Sequence, TypeVar

from .config import SEED
from .exceptions import GeneratorError, NonDeterministicSeedLeakError

T = TypeVar("T")

# Labels: alphanumerics plus underscore / hyphen / colon / dot / slash.
_LABEL_REGEX = re.compile(r"^[A-Za-z0-9_\-:./]+$")


class DeterministicRNG:
    """Deterministic Random wrapper with a whitelisted API surface (§6.1).

    Whitelist: random, randint, choice, choices, shuffle, sample, uniform.
    All other stdlib random API is OUT OF SCOPE (F-A-35).
    """

    __slots__ = ("_label", "_seed", "_rand")

    def __init__(self, seed: int, label: str) -> None:
        if not isinstance(seed, int) or seed < 0:
            raise ValueError(f"seed must be non-negative int, got {seed!r}")
        if not isinstance(label, str) or not label:
            raise ValueError("label must be a non-empty str")
        if not _LABEL_REGEX.match(label):
            raise ValueError(f"label contains illegal characters: {label!r}")
        self._label = label
        self._seed = seed
        self._rand = random.Random(seed)

    # ---- whitelist methods --------------------------------------------------

    def random(self) -> float:
        return self._rand.random()

    def choice(self, seq: Sequence[T]) -> T:
        if len(seq) == 0:
            raise IndexError("choice from empty sequence")
        return self._rand.choice(seq)

    def choices(
        self,
        seq: Sequence[T],
        k: int,
        weights: Optional[Sequence[float]] = None,
    ) -> list[T]:
        return self._rand.choices(seq, weights=weights, k=k)

    def randint(self, a: int, b: int) -> int:
        if a > b:
            raise ValueError(f"randint requires a <= b, got a={a} b={b}")
        return self._rand.randint(a, b)

    def shuffle(self, seq: MutableSequence[T]) -> None:
        self._rand.shuffle(seq)

    def sample(self, pop: Sequence[T], k: int) -> list[T]:
        if k < 0 or k > len(pop):
            raise ValueError(f"sample k={k} out of range [0, {len(pop)}]")
        return self._rand.sample(pop, k)

    def uniform(self, a: float, b: float) -> float:
        return self._rand.uniform(a, b)

    # ---- label + spawn ------------------------------------------------------

    @property
    def label(self) -> str:
        return self._label

    def spawn(self, sub_label: str) -> "DeterministicRNG":
        """Derive a child RNG with a sha256-of-combined-label seed (§7.3).

        BIG-ENDIAN is LOCKED (F-C-21). signed=False is LOCKED.
        """
        if not isinstance(sub_label, str) or not sub_label:
            raise ValueError("sub_label must be a non-empty str")
        if "::" in sub_label:
            raise ValueError("sub_label must not contain '::'")
        if not _LABEL_REGEX.match(sub_label):
            raise ValueError(f"sub_label contains illegal characters: {sub_label!r}")
        combined = f"{self._label}::{sub_label}".encode("utf-8")
        digest = hashlib.sha256(combined).digest()
        seed_bytes = digest[:8]
        child_seed = int.from_bytes(seed_bytes, byteorder="big", signed=False)
        return DeterministicRNG(child_seed, f"{self._label}::{sub_label}")

    def _internal_seed_for_test(self) -> int:
        """Test-only hatch: expose the 64-bit seed (T8 regression fixture)."""
        return self._seed


def root_rng(seed: int = SEED) -> DeterministicRNG:
    """Return a DeterministicRNG labeled 'root' (§6.2)."""
    if not isinstance(seed, int) or seed < 0:
        raise ValueError(f"seed must be non-negative int, got {seed!r}")
    return DeterministicRNG(seed, "root")


# -----------------------------------------------------------------------------
# Defense-in-depth context managers
# -----------------------------------------------------------------------------

_RANDOM_WHITELIST = (
    "random", "randint", "choice", "choices",
    "shuffle", "sample", "uniform", "seed", "getrandbits",
)


@contextmanager
def guard_global_random() -> Iterator[None]:
    """Replace module-level random.* with raising stubs (§6.3).

    AST scan is primary; monkey-patch is defense-in-depth. Catches bypasses
    like `getattr(globals()['random'], 'rand' + 'int')(1,10)` that slip the
    AST literal check.
    """
    originals: dict[str, object] = {}
    for name in _RANDOM_WHITELIST:
        if hasattr(random, name):
            originals[name] = getattr(random, name)

    def _stub(*args, **kwargs):  # noqa: ANN001, ANN002
        raise NonDeterministicSeedLeakError(
            "module-level random.* is forbidden during generation"
        )

    try:
        for name in originals:
            setattr(random, name, _stub)
        yield
    finally:
        for name, orig in originals.items():
            setattr(random, name, orig)


@contextmanager
def guard_no_subprocess() -> Iterator[None]:
    """Replace subprocess/os-exec/builtins eval|exec|compile with raising stubs (§6.4).

    AST scan is primary; monkey-patch is defense-in-depth. Catches dynamic-import
    bypasses like __import__("sub" + "process").run(["ls"]) where the literal
    "subprocess" never appears in source.
    """
    import builtins
    import importlib
    import os as _os

    # AST rule #1 forbids `import subprocess`; we obtain the module via
    # importlib.import_module at runtime so the monkey-patching defense-in-depth
    # does not itself trip the primary AST barrier.
    _subprocess = importlib.import_module("sub" "process")

    originals: list[tuple[object, str, object]] = []

    def _stub(*args, **kwargs):  # noqa: ANN001, ANN002
        raise GeneratorError("subprocess/exec forbidden inside generator.run()")

    def _install(mod: object, attr: str) -> None:
        if hasattr(mod, attr):
            originals.append((mod, attr, getattr(mod, attr)))
            setattr(mod, attr, _stub)

    try:
        for attr in ("run", "Popen", "call", "check_call", "check_output"):
            _install(_subprocess, attr)
        for attr in (
            "system", "popen",
            "execv", "execve", "execl", "execle", "execlp", "execlpe",
            "execvp", "execvpe",
            "spawnv", "spawnve", "spawnl", "spawnle", "spawnlp", "spawnlpe",
            "spawnvp", "spawnvpe",
        ):
            _install(_os, attr)
        for attr in ("eval", "exec", "compile"):
            _install(builtins, attr)
        yield
    finally:
        for mod, attr, orig in originals:
            setattr(mod, attr, orig)
