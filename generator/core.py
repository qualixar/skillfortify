"""BenchmarkGenerator orchestrator + frozen dataclasses (LLD-01 §4, §6.11, §7.8, §7.10).

Contains:
- Frozen dataclasses: SkillSpec, RenderedSkill, ManifestEntry, TaxonomyDoc,
  GenerationReport, PerSkillHash, RunMetadata
- _assert_safe_output_root (§7.8) — 12 rejection rules (R-SR-0..R-SR-11)
- BenchmarkGenerator — __init__ + run() per §6.11 + §7.10
"""

from __future__ import annotations

import importlib.metadata
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Iterator, Mapping, Optional

from .config import (
    BENIGN_CATEGORIES,
    DANGEROUS_ABS_PREFIXES,
    DANGEROUS_HOME_COMPONENTS,
    FORMATS,
    PARSER_ROUNDTRIP_REQUIRED,
    SEED,
    TABLE_11_DISTRIBUTION,
)
from .enforce import enforce_table_11
from .exceptions import (
    ForbiddenWordError,
    PreflightViolationError,
    RegistryIncompleteError,
    UnsafeOutputRootError,
)
from .hashing import sha256_lf
from .preflight import (
    ast_scan_package,
    assert_pythonhashseed_zero_equiv,
    assert_single_process,
)
from .registry import AttackPatternProtocol, BenignCategoryProtocol
from .rng import guard_global_random, guard_no_subprocess, root_rng
from .writer import ManifestWriter, TaxonomyWriter, _forbidden_words_check


# =============================================================================
# Frozen data types (§4)
# =============================================================================


@dataclass(frozen=True, slots=True)
class SkillSpec:
    skill_id: str
    format: str
    is_malicious: bool
    attack_type: str
    parent_class: str
    benign_category: Optional[str]
    skill_index: int
    obfuscation_level: Optional[str]
    is_canary: bool = False


@dataclass(frozen=True, slots=True)
class RenderedSkill:
    spec: SkillSpec
    filename: str
    content_bytes: bytes
    format_extension: str
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    skill_id: str
    format: str
    is_malicious: bool
    attack_type: str
    parent_class: str
    benign_category: Optional[str]
    source_attribution: tuple[str, ...]
    obfuscation_level: Optional[str]
    filename: str
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class TaxonomyDoc:
    schema_version: str
    paper_section: str
    formal_classes: Mapping[str, Mapping[str, object]]
    attack_types: Mapping[str, Mapping[str, object]]
    benign_categories: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PerSkillHash:
    skill_id: str
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class RunMetadata:
    generator_version: str
    pyproject_source: str
    python_implementation: str
    python_version: str
    platform_system: str


@dataclass(frozen=True, slots=True)
class GenerationReport:
    seed: int
    total_skills: int
    per_format_counts: Mapping[str, int]
    per_attack_type_counts: Mapping[tuple[str, str], int]
    per_skill_hashes: tuple[PerSkillHash, ...]
    manifest_content_sha256: str
    taxonomy_sha256: str
    generator_version: str
    run_metadata: RunMetadata


# =============================================================================
# _assert_safe_output_root — 12 rejection rules (§7.8)
# =============================================================================


_SHELL_METACHARS: Final[tuple[str, ...]] = ("*", "?", "[", "]", "`", "$(")


def _assert_safe_output_root(path: Path, *, project_root: Path) -> None:
    """Validate path per R-SR-0..R-SR-11. Raise UnsafeOutputRootError on any rejection.

    Rule order preserved per LLD §7.8 so callers may rely on the first-match rule
    name in exception messages (tests use `match=<rule_name>` regex).
    """

    # R-SR-0: empty or null
    if path is None:
        raise UnsafeOutputRootError(path, "empty_or_null", "path is None")
    p_str = str(path)
    if p_str == "" or p_str == ".":
        raise UnsafeOutputRootError(path, "empty_or_null", f"empty path: {p_str!r}")

    if not isinstance(path, Path):
        path = Path(path)

    # R-SR-11 (partial — cheap metachar + NUL + length + ".." component checks first
    # for robustness, but we report after R-SR-0..R-SR-2 for rule-name ordering).

    # R-SR-1: not absolute
    if not path.is_absolute():
        raise UnsafeOutputRootError(path, "not_absolute", f"not absolute: {path}")

    # R-SR-2: filesystem root
    if str(path) == "/" or path.parts == ("/",):
        raise UnsafeOutputRootError(path, "filesystem_root", f"filesystem root: {path}")

    # R-SR-3: user-home root
    home_equivalents: list[str] = []
    try:
        home_equivalents.append(str(Path("~").expanduser()))
    except Exception:
        pass
    env_home = os.path.expandvars("$HOME")
    if env_home and env_home != "$HOME":
        home_equivalents.append(env_home)
    # Add literal /root
    home_equivalents.append("/root")
    # macOS / Linux fallbacks derived from the HOME env-var expansion only —
    # os.getlogin() is deliberately avoided (AST preflight rule #19).
    # Literal unexpanded forms as components are also rejected.
    for comp in path.parts:
        if comp in ("~", "$HOME", "$USER"):
            raise UnsafeOutputRootError(
                path, "user_home_root", f"unexpanded home component: {comp}"
            )
    for eq in home_equivalents:
        if str(path) == eq:
            raise UnsafeOutputRootError(
                path, "user_home_root", f"path equals home-equivalent: {eq}"
            )

    # R-SR-4: too shallow (< 4 components). parts includes "/" as first.
    if len(path.parts) < 4:
        raise UnsafeOutputRootError(
            path, "too_shallow", f"len(parts)={len(path.parts)} < 4: {path}"
        )

    # R-SR-9: dot_backup_ancestor — any component named ".backup"
    if ".backup" in path.parts:
        raise UnsafeOutputRootError(
            path, "dot_backup_ancestor", f".backup component in path: {path}"
        )

    # R-SR-11: shell metachars / ".." / length / NUL byte
    if len(p_str) > 1024:
        raise UnsafeOutputRootError(
            path, "shell_or_traversal_metachar", f"path too long: len={len(p_str)}"
        )
    if "\x00" in p_str:
        raise UnsafeOutputRootError(
            path, "shell_or_traversal_metachar", "NUL byte in path"
        )
    for meta in _SHELL_METACHARS:
        if meta in p_str:
            raise UnsafeOutputRootError(
                path,
                "shell_or_traversal_metachar",
                f"shell metachar {meta!r} in path",
            )
    if ".." in path.parts:
        raise UnsafeOutputRootError(
            path, "shell_or_traversal_metachar", "'..' component in path"
        )

    # R-SR-5: resolve(strict=True); fallback to parent-resolve(strict=True)
    try:
        path.resolve(strict=True)
    except (FileNotFoundError, OSError):
        try:
            parent = path.parent
            parent.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise UnsafeOutputRootError(
                path, "resolve_failed", f"resolve failed: {exc}"
            ) from exc

    # R-SR-6: path itself is a symlink
    if path.is_symlink():
        raise UnsafeOutputRootError(
            path, "path_is_symlink", f"path is symlink: {path}"
        )

    # R-SR-7: any ancestor is a symlink (walk up to "/")
    ancestor = path.parent
    sentinel = Path(ancestor.anchor or "/")
    steps = 0
    while ancestor != sentinel and steps < 256:
        if ancestor.is_symlink():
            raise UnsafeOutputRootError(
                path, "ancestor_symlink", f"ancestor symlink: {ancestor}"
            )
        new_ancestor = ancestor.parent
        if new_ancestor == ancestor:
            break
        ancestor = new_ancestor
        steps += 1

    # R-SR-8: escape_project_root — realpath containment under project_root realpath
    real_p = os.path.realpath(str(path))
    real_project = os.path.realpath(str(project_root))
    if real_p != real_project and not real_p.startswith(real_project + os.sep):
        raise UnsafeOutputRootError(
            path,
            "escape_project_root",
            f"{real_p} is not under project root {real_project}",
        )

    # R-SR-10: dangerous ancestor paths
    # Absolute dangerous prefixes.
    for prefix in DANGEROUS_ABS_PREFIXES:
        if real_p == prefix or real_p.startswith(prefix + os.sep):
            # However, on macOS /var is a symlink to /private/var. A project
            # under /Users should never hit these. If the project_root itself
            # is under the same prefix, defer to R-SR-8 containment decision.
            if real_project == prefix or real_project.startswith(prefix + os.sep):
                continue
            raise UnsafeOutputRootError(
                path,
                "dangerous_ancestor",
                f"dangerous absolute ancestor {prefix}",
            )
    # Home-relative dangerous components (only reject if path is NOT within project_root,
    # i.e., R-SR-8 already established containment inside project_root, so treat
    # home-relative dangerous components as a concern only when project_root itself
    # is NOT under the same home-relative dangerous subtree).
    try:
        home_real = os.path.realpath(str(Path.home()))
    except Exception:
        home_real = ""
    if home_real:
        for comp in DANGEROUS_HOME_COMPONENTS:
            dangerous_sub = os.path.join(home_real, comp)
            inside_path = (
                real_p == dangerous_sub or real_p.startswith(dangerous_sub + os.sep)
            )
            inside_project = (
                real_project == dangerous_sub
                or real_project.startswith(dangerous_sub + os.sep)
            )
            if inside_path and not inside_project:
                raise UnsafeOutputRootError(
                    path,
                    "dangerous_ancestor",
                    f"dangerous home-relative component {comp}",
                )


# =============================================================================
# BenchmarkGenerator
# =============================================================================


# Module-level constant: root of the generator package for preflight scanning.
_BENCHMARKS_GENERATOR_ROOT: Final[Path] = Path(__file__).resolve().parent


def _default_project_root_from_cwd() -> Path:
    """Walk up from CWD looking for pyproject.toml. Raise if not found."""
    cur = Path(os.getcwd()).resolve()
    for candidate in [cur, *cur.parents]:
        if (candidate / "pyproject.toml").exists():
            return candidate
    raise FileNotFoundError(
        "Could not locate project_root (pyproject.toml not found from CWD)."
    )


def _pkg_version_safe() -> str:
    """Return generator version, falling back to '0.0.0-dev' when package metadata
    is unavailable (benchmarks package is not installed as a distribution).
    """
    try:
        return importlib.metadata.version("benchmarks")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0-dev"


class BenchmarkGenerator:
    """Top-level orchestrator (LLD-01 §6.11 + §7.10)."""

    def __init__(
        self,
        *,
        output_root: Path,
        seed: int = SEED,
        attack_registry: Mapping[str, AttackPatternProtocol],
        benign_registry: Mapping[str, BenignCategoryProtocol],
        attack_type_to_class: Mapping[str, str],
        pythonhashseed_observed: str,
        project_root_override: Optional[Path] = None,
        parser_roundtrip: Optional[bool] = None,
        dry_run: bool = False,
        verify_only: bool = False,
        _permit_empty_registries: bool = False,
    ) -> None:
        # Preflight 1: PYTHONHASHSEED observation
        assert_pythonhashseed_zero_equiv(pythonhashseed_observed)

        # Preflight 2: single process
        assert_single_process()

        # Preflight 3: AST scan of generator package itself
        violations = ast_scan_package(_BENCHMARKS_GENERATOR_ROOT)
        if violations:
            raise PreflightViolationError(violations)

        # Resolve project_root (used by safe-output-root rules R-SR-8/R-SR-10)
        if project_root_override is not None:
            project_root = Path(project_root_override).resolve()
        else:
            project_root = _default_project_root_from_cwd()

        # Preflight 4: safe output root (skip in verify_only mode)
        if not verify_only:
            _assert_safe_output_root(Path(output_root), project_root=project_root)

        # Registry completeness checks (skipped by test-only hatch)
        if not _permit_empty_registries:
            _check_registries(
                attack_registry, benign_registry, attack_type_to_class
            )

        # Store state
        self._output_root = Path(output_root)
        self._project_root = project_root
        self._seed = seed
        self._attack_registry = dict(attack_registry)
        self._benign_registry = dict(benign_registry)
        self._attack_type_to_class = dict(attack_type_to_class)
        self._dry_run = dry_run
        self._verify_only = verify_only
        self._permit_empty_registries = _permit_empty_registries
        self._parser_roundtrip = (
            PARSER_ROUNDTRIP_REQUIRED if parser_roundtrip is None else bool(parser_roundtrip)
        )

    # -- generation ----------------------------------------------------------

    def _generation_order(self) -> Iterator[SkillSpec]:
        """Yield SkillSpec records in canonical order (§7.2).

        When attack_type_to_class or benign_registry is empty (test hatch), the
        respective inner loop is skipped so total yield can be zero for bones tests.
        """
        attack_types = [f"A{i}" for i in range(1, 14)]
        for fmt in FORMATS:
            # Malicious first
            if self._attack_type_to_class:
                for atype in attack_types:
                    key = (fmt, atype)
                    K = TABLE_11_DISTRIBUTION[key]
                    parent_cls = self._attack_type_to_class.get(atype, "unknown")
                    for i in range(1, K + 1):
                        skill_id = _build_skill_id(
                            fmt=fmt, is_malicious=True,
                            attack_type=atype, benign_category=None,
                            skill_index=i,
                        )
                        yield SkillSpec(
                            skill_id=skill_id,
                            format=fmt,
                            is_malicious=True,
                            attack_type=atype,
                            parent_class=parent_cls,
                            benign_category=None,
                            skill_index=i,
                            obfuscation_level=None,
                        )
            # Benign second
            if self._benign_registry:
                for cat in BENIGN_CATEGORIES:
                    for i in range(1, 19):
                        skill_id = _build_skill_id(
                            fmt=fmt, is_malicious=False,
                            attack_type="benign", benign_category=cat,
                            skill_index=i,
                        )
                        yield SkillSpec(
                            skill_id=skill_id,
                            format=fmt,
                            is_malicious=False,
                            attack_type="benign",
                            parent_class="benign",
                            benign_category=cat,
                            skill_index=i,
                            obfuscation_level=None,
                        )

    def run(self) -> GenerationReport:
        """Top-level generation sequence (§7.10)."""
        # Re-run single-process check at run() entry (belt + suspenders).
        assert_single_process()

        gen_version = _pkg_version_safe()
        # Forbidden-word check on the derived version string.
        _forbidden_words_check(gen_version)

        # Re-assert safe root unless verify_only (already done in __init__, but
        # cheap and defensive).
        if not self._verify_only:
            _assert_safe_output_root(self._output_root, project_root=self._project_root)

        entries: list[ManifestEntry] = []
        per_format_counts: dict[str, int] = {fmt: 0 for fmt in FORMATS}
        per_attack_type_counts: dict[tuple[str, str], int] = {}

        with guard_no_subprocess(), guard_global_random():
            rng_root = root_rng(seed=self._seed)

            from .writer import SkillWriter

            for spec in self._generation_order():
                sub_label = (
                    f"{spec.format}/"
                    f"{'mal' if spec.is_malicious else 'ben'}/"
                    f"{spec.attack_type if spec.is_malicious else spec.benign_category}/"
                    f"{spec.skill_index:03d}"
                )
                rng_child = rng_root.spawn(sub_label)

                if spec.is_malicious:
                    pattern = self._attack_registry.get(spec.attack_type)
                    if pattern is None:
                        raise RegistryIncompleteError(
                            missing=(spec.attack_type,), kind="attack"
                        )
                    rendered = pattern.instantiate(spec, rng_child)
                else:
                    cat = self._benign_registry.get(spec.benign_category)
                    if cat is None:
                        raise RegistryIncompleteError(
                            missing=(spec.benign_category,), kind="benign"
                        )
                    rendered = cat.instantiate(spec, rng_child)

                digest = sha256_lf(rendered.content_bytes)

                if not self._dry_run:
                    writer = SkillWriter(self._output_root, project_root=self._project_root)
                    path_written = writer.write(rendered)
                    rel_path = str(path_written.relative_to(self._output_root))
                else:
                    subdir = "malicious" if spec.is_malicious else "benign"
                    rel_path = f"skills/{spec.format}/{subdir}/{rendered.filename}"

                entry = ManifestEntry(
                    skill_id=spec.skill_id,
                    format=spec.format,
                    is_malicious=spec.is_malicious,
                    attack_type=spec.attack_type,
                    parent_class=spec.parent_class,
                    benign_category=spec.benign_category,
                    source_attribution=rendered.sources,
                    obfuscation_level=spec.obfuscation_level,
                    filename=rendered.filename,
                    path=rel_path,
                    sha256=digest,
                )
                entries.append(entry)
                per_format_counts[spec.format] = per_format_counts.get(spec.format, 0) + 1
                key = (spec.format, spec.attack_type if spec.is_malicious else "benign")
                per_attack_type_counts[key] = per_attack_type_counts.get(key, 0) + 1

            # Table 11 enforcement — skip under _permit_empty_registries hatch.
            if not self._permit_empty_registries:
                enforce_table_11(entries)

            # Run metadata
            run_metadata = RunMetadata(
                generator_version=gen_version,
                pyproject_source="benchmarks/pyproject.toml",
                python_implementation=platform.python_implementation(),
                python_version=platform.python_version(),
                platform_system=platform.system(),
            )

            manifest_content_sha256 = ""
            if not self._dry_run:
                _, manifest_content_sha256 = ManifestWriter().write(
                    self._output_root, entries, run_metadata
                )
                # Always emit attack_taxonomy.json even when empty (keeps schema stable).
                taxonomy = TaxonomyDoc(
                    schema_version="1.0",
                    paper_section="§3.2 + §8.1 + §B.1",
                    formal_classes={},
                    attack_types={
                        atype: {"parent_class": cls}
                        for atype, cls in self._attack_type_to_class.items()
                    },
                    benign_categories=BENIGN_CATEGORIES,
                )
                tax_path = TaxonomyWriter().write(self._output_root, taxonomy)
                taxonomy_sha = sha256_lf(tax_path.read_bytes())
            else:
                taxonomy_sha = ""

        return GenerationReport(
            seed=self._seed,
            total_skills=len(entries),
            per_format_counts=per_format_counts,
            per_attack_type_counts=per_attack_type_counts,
            per_skill_hashes=tuple(
                PerSkillHash(e.skill_id, e.path, e.sha256) for e in entries
            ),
            manifest_content_sha256=manifest_content_sha256,
            taxonomy_sha256=taxonomy_sha,
            generator_version=gen_version,
            run_metadata=run_metadata,
        )


# =============================================================================
# Helpers
# =============================================================================


def _build_skill_id(
    *,
    fmt: str,
    is_malicious: bool,
    attack_type: str,
    benign_category: Optional[str],
    skill_index: int,
) -> str:
    """skill_id derivation per §7.1."""
    kind = "mal" if is_malicious else "ben"
    if is_malicious:
        num = int(attack_type[1:])
        type_slug = f"A{num:02d}"
    else:
        if benign_category is None:
            raise ValueError("benign spec requires benign_category")
        idx1 = BENIGN_CATEGORIES.index(benign_category) + 1
        type_slug = f"cat{idx1}"
    padded = f"{skill_index:03d}"
    return f"{fmt}_{kind}_{type_slug}_{padded}"


def _check_registries(
    attack_registry: Mapping[str, AttackPatternProtocol],
    benign_registry: Mapping[str, BenignCategoryProtocol],
    attack_type_to_class: Mapping[str, str],
) -> None:
    """Verify A1..A13 attacks and the 5 benign categories are present."""
    expected_attacks = {f"A{i}" for i in range(1, 14)}
    missing_attacks = tuple(sorted(expected_attacks - set(attack_registry)))
    if missing_attacks:
        raise RegistryIncompleteError(missing=missing_attacks, kind="attack")
    missing_map = tuple(sorted(expected_attacks - set(attack_type_to_class)))
    if missing_map:
        raise RegistryIncompleteError(missing=missing_map, kind="attack_type_to_class")
    expected_benign = set(BENIGN_CATEGORIES)
    missing_benign = tuple(sorted(expected_benign - set(benign_registry)))
    if missing_benign:
        raise RegistryIncompleteError(missing=missing_benign, kind="benign")


# Suppress "unused import" warning for ForbiddenWordError (re-exported via exceptions).
_ = ForbiddenWordError
