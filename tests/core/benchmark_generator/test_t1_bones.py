"""Stage 6 Track T1 — BenchmarkGenerator bones (LLD-01 §§1-6 + §7 pseudocode).

18 RED tests covering:
- DeterministicRNG whitelist + spawn + guards (5 tests)
- AST preflight 19-rule scan (4 tests)
- _assert_safe_output_root 12-rule rejection (3 tests)
- sha256_lf LF-normalization + ManifestWriter byte-stability + atomic writer (3 tests)
- enforce_table_11 distribution validator (2 tests)
- Integration: empty-registries byte-identical run (1 test)

All tests match test IDs in LLD-01 §12.1 + §12.2 (T-SEC-*, T-DET-*). Reference LLD
section numbers in docstrings so the implementer knows which spec block drives each
assertion.

Safety: INERT TEXT ONLY. Tests never exec/import untrusted content. AST preflight
fixtures are written via Path.write_text, scanned as TEXT, never executed as Python.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Test 1-5 — DeterministicRNG (LLD-01 §6.1 + §6.3 + §6.4 + §7.3)
# ---------------------------------------------------------------------------


def test_deterministic_rng_whitelist_methods_stable():
    """§6.1 whitelist: random, randint, choice, choices, shuffle, sample, uniform.

    Two RNGs seeded identically must emit identical sequences across whitelisted
    methods. Proves PHASE-01 determinism contract (paper §B.3 Principle 2).
    """
    from benchmarks.generator.rng import DeterministicRNG

    a = DeterministicRNG(42, "root")
    b = DeterministicRNG(42, "root")

    assert a.randint(0, 1000) == b.randint(0, 1000)
    assert a.choice([1, 2, 3, 4, 5]) == b.choice([1, 2, 3, 4, 5])
    assert a.choices(["x", "y", "z"], k=5) == b.choices(["x", "y", "z"], k=5)
    assert a.sample([10, 20, 30, 40, 50], k=3) == b.sample([10, 20, 30, 40, 50], k=3)
    # random() added to whitelist per F-A-35
    assert a.random() == b.random()
    # uniform
    assert a.uniform(0.0, 100.0) == b.uniform(0.0, 100.0)

    # shuffle mutates in place; both inputs must end up identical
    la = [1, 2, 3, 4, 5]
    lb = [1, 2, 3, 4, 5]
    a.shuffle(la)
    b.shuffle(lb)
    assert la == lb


def test_deterministic_rng_spawn_big_endian_stable():
    """§7.3 + F-C-21: spawn uses sha256(label::sub_label)[:8] int.from_bytes big-endian.

    Canonical fixture: child_seed for (root, alpha) is a fixed 64-bit value.
    Endianness is LOCKED. Any regression = major version bump.
    """
    from benchmarks.generator.rng import DeterministicRNG

    parent = DeterministicRNG(42, "root")
    child = parent.spawn("alpha")

    expected_digest = hashlib.sha256(b"root::alpha").digest()[:8]
    expected_seed = int.from_bytes(expected_digest, byteorder="big", signed=False)

    # Expose for testing via _internal_seed_for_test() per §12 T8
    assert hasattr(child, "_internal_seed_for_test"), (
        "DeterministicRNG must expose _internal_seed_for_test() for spawn regression tests"
    )
    assert child._internal_seed_for_test() == expected_seed
    assert child.label == "root::alpha"


def test_deterministic_rng_rejects_forbidden_methods():
    """§6.1 whitelist is EXHAUSTIVE. gauss/normalvariate/triangular → AttributeError.

    F-A-35: "All other stdlib random API surface is OUT OF SCOPE for v1.0."
    """
    from benchmarks.generator.rng import DeterministicRNG

    rng = DeterministicRNG(42, "test")

    for forbidden in ("gauss", "normalvariate", "triangular", "betavariate", "expovariate"):
        assert not hasattr(rng, forbidden) or not callable(
            getattr(rng, forbidden, None)
        ), f"DeterministicRNG must not expose {forbidden!r} (whitelist violation)"


def test_guard_global_random_raises_on_module_call():
    """§6.3 guard_global_random: module-level random.random() inside guard → raise.

    Defense-in-depth secondary layer (primary is AST rule #14). Catches bypasses
    like `globals()['random'].random()` that slip AST literal checks.
    """
    import random as _random

    from benchmarks.generator.exceptions import NonDeterministicSeedLeakError
    from benchmarks.generator.rng import guard_global_random

    with pytest.raises(NonDeterministicSeedLeakError):
        with guard_global_random():
            _random.random()  # inside guard — must raise


def test_guard_no_subprocess_raises_on_invocation():
    """§6.4 guard_no_subprocess: subprocess.run() inside guard → GeneratorError.

    Defense-in-depth secondary layer (primary is AST rules #1-#13).
    """
    import subprocess as _subprocess

    from benchmarks.generator.exceptions import GeneratorError
    from benchmarks.generator.rng import guard_no_subprocess

    with pytest.raises(GeneratorError):
        with guard_no_subprocess():
            _subprocess.run(["echo", "nope"], check=False)


# ---------------------------------------------------------------------------
# Test 6-9 — AST preflight scan (LLD-01 §4.3)
# ---------------------------------------------------------------------------


def _write_fixture_package(tmp_path: Path, filename: str, source: str) -> Path:
    """Create an inert fixture package with one .py file containing `source`.

    INERT TEXT ONLY: the file is written as bytes and never imported/exec'd.
    The AST scan reads the source text and parses it via ast.parse — no execution.
    """
    pkg = tmp_path / "fixture_pkg"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    rogue = pkg / filename
    rogue.write_text(source, encoding="utf-8")
    return pkg


def test_preflight_rejects_planted_subprocess_import(tmp_path):
    """§4.3.2 rule #1 forbid_subprocess_import: `import subprocess` → Violation.

    Maps to T-SEC-6. Primary safety barrier per Varun D6.
    """
    from benchmarks.generator.preflight import ast_scan_package

    pkg = _write_fixture_package(tmp_path, "rogue.py", "import subprocess\n")
    violations = ast_scan_package(pkg)

    assert any(v.rule == "forbid_subprocess_import" for v in violations), (
        f"Expected forbid_subprocess_import violation, got rules: "
        f"{[v.rule for v in violations]}"
    )


def test_preflight_rejects_getattr_os_dynamic(tmp_path):
    """§4.3.2 rule #7 forbid_os_dynamic_attr: `getattr(os, 'sys'+'tem')` → Violation.

    Maps to T-SEC-8. Catches indirect-attr bypass.
    """
    from benchmarks.generator.preflight import ast_scan_package

    pkg = _write_fixture_package(
        tmp_path,
        "rogue.py",
        'import os\ngetattr(os, "sys" + "tem")("whoami")\n',
    )
    violations = ast_scan_package(pkg)

    assert any(v.rule == "forbid_os_dynamic_attr" for v in violations), (
        f"Expected forbid_os_dynamic_attr violation, got rules: "
        f"{[v.rule for v in violations]}"
    )


def test_preflight_rejects_module_level_random_random(tmp_path):
    """§4.3.2 rule #14 forbid_module_level_random: `random.random()` at module scope.

    F-A-35: DeterministicRNG is the required path. Module-level random.* is rejected.
    """
    from benchmarks.generator.preflight import ast_scan_package

    pkg = _write_fixture_package(
        tmp_path,
        "rogue.py",
        "import random\nVAL = random.random()\n",
    )
    violations = ast_scan_package(pkg)

    assert any(v.rule == "forbid_module_level_random" for v in violations), (
        f"Expected forbid_module_level_random violation, got rules: "
        f"{[v.rule for v in violations]}"
    )


def test_preflight_accepts_clean_module(tmp_path):
    """Clean stdlib-only module → zero violations.

    Negative control: proves scan does not over-flag legitimate patterns.
    """
    from benchmarks.generator.preflight import ast_scan_package

    clean_source = (
        '"""Clean module."""\n'
        "from pathlib import Path\n"
        "from typing import Final\n"
        "\n"
        "SOME_CONST: Final[int] = 42\n"
        "\n"
        "def add(a: int, b: int) -> int:\n"
        "    return a + b\n"
    )
    pkg = _write_fixture_package(tmp_path, "clean.py", clean_source)
    violations = ast_scan_package(pkg)

    # Filter out violations from __init__.py (empty, should be clean too)
    non_init_violations = [v for v in violations if "clean.py" in v.file]
    assert non_init_violations == [], (
        f"Clean module should produce zero violations, got: {non_init_violations}"
    )


# ---------------------------------------------------------------------------
# Test 10-12 — _assert_safe_output_root (LLD-01 §7.8)
# ---------------------------------------------------------------------------


def test_safe_output_root_rejects_filesystem_root(project_root):
    """§7.8 R-SR-2 filesystem_root: Path('/') → UnsafeOutputRootError."""
    from benchmarks.generator.core import _assert_safe_output_root
    from benchmarks.generator.exceptions import UnsafeOutputRootError

    with pytest.raises(UnsafeOutputRootError, match="filesystem_root"):
        _assert_safe_output_root(Path("/"), project_root=project_root)


def test_safe_output_root_rejects_under_backup(project_root):
    """§7.8 R-SR-9 dot_backup_ancestor: any `.backup` component → reject.

    D7 defense-in-depth. LLD-08 owns the primary check; generator rejects a
    second time to prevent accidental write INTO private register.
    """
    from benchmarks.generator.core import _assert_safe_output_root
    from benchmarks.generator.exceptions import UnsafeOutputRootError

    # Construct a path inside project_root that has `.backup` as a component
    bad_path = project_root / ".backup" / "output_run_a"
    with pytest.raises(UnsafeOutputRootError, match="dot_backup_ancestor"):
        _assert_safe_output_root(bad_path, project_root=project_root)


def test_safe_output_root_rejects_symlink_escape(tmp_path, project_root):
    """§7.8 R-SR-6 path_is_symlink: symlinked output_root → reject.

    Per F-C-01 + F-C-24: prevents symlink-escape attack.
    """
    from benchmarks.generator.core import _assert_safe_output_root
    from benchmarks.generator.exceptions import UnsafeOutputRootError

    # Create a symlink inside project_root pointing to /tmp
    scratch = project_root / ".skfval-tmp"
    scratch.mkdir(exist_ok=True)
    link_path = scratch / f"link_sym_{os.getpid()}_{id(tmp_path)}"
    if link_path.exists() or link_path.is_symlink():
        link_path.unlink()
    link_path.symlink_to("/tmp")

    try:
        with pytest.raises(UnsafeOutputRootError):
            _assert_safe_output_root(link_path, project_root=project_root)
    finally:
        if link_path.is_symlink():
            link_path.unlink()


# ---------------------------------------------------------------------------
# Test 13-15 — sha256_lf + ManifestWriter byte-stability + atomic writer
# ---------------------------------------------------------------------------


def test_sha256_lf_normalizes_crlf_and_cr_to_lf():
    """§6.13 + F-C-29: sha256_lf(CRLF) == sha256_lf(LF) == sha256_lf(CR).

    Maps to T12. Core determinism primitive — symmetric write-path and read-path.
    """
    from benchmarks.generator.hashing import sha256_lf

    digest_lf = sha256_lf(b"hello\n")
    digest_crlf = sha256_lf(b"hello\r\n")
    digest_cr = sha256_lf(b"hello\r")

    assert digest_lf == digest_crlf == digest_cr, (
        f"Line-ending normalization failed: LF={digest_lf} CRLF={digest_crlf} CR={digest_cr}"
    )
    # Also verify the expected normalized digest
    assert digest_lf == hashlib.sha256(b"hello\n").hexdigest()
    assert len(digest_lf) == 64
    assert digest_lf == digest_lf.lower()


def test_manifest_writer_byte_stable_across_runs(safe_output_root, project_root):
    """§7.12 + I-DET-1: two writes of same entries produce identical bytes.

    Core byte-identity invariant (INV-20 cross-LLD). Establishes baseline that the
    empty-registries integration test later extends to the full run() path.
    """
    from benchmarks.generator.core import ManifestEntry, RunMetadata
    from benchmarks.generator.writer import ManifestWriter

    entries: list[ManifestEntry] = []  # empty entries — minimal bones case
    run_meta = RunMetadata(
        generator_version="1.0.0",
        pyproject_source="benchmarks/pyproject.toml",
        python_implementation="CPython",
        python_version="3.11.9",
        platform_system="Linux",
    )

    run_a = safe_output_root / "run_a"
    run_b = safe_output_root / "run_b"
    run_a.mkdir()
    run_b.mkdir()

    writer = ManifestWriter()
    path_a, sha_a = writer.write(run_a, entries, run_meta)
    path_b, sha_b = writer.write(run_b, entries, run_meta)

    # manifest_content_sha256 must match (content is entries-only, identical)
    assert sha_a == sha_b, f"manifest_content_sha256 differs: {sha_a} vs {sha_b}"

    # Full file bytes also match since run_metadata identical here
    bytes_a = path_a.read_bytes()
    bytes_b = path_b.read_bytes()
    assert bytes_a == bytes_b, (
        "manifest.json byte-identity failed across two identical-input runs"
    )


def test_skill_writer_rejects_cross_fs_tempfile(safe_output_root, project_root):
    """§7.4 F-C-24: os.replace atomicity requires same-filesystem tempfile.

    If tempfile lands on a different st_dev than target_dir, SkillWriter MUST
    raise OSError before any disk mutation.
    """
    from benchmarks.generator.core import RenderedSkill, SkillSpec
    from benchmarks.generator.writer import SkillWriter

    spec = SkillSpec(
        skill_id="claude_mal_A01_001",
        format="claude",
        is_malicious=True,
        attack_type="A1",
        parent_class="c1_DATA_EXFILTRATION",
        benign_category=None,
        skill_index=1,
        obfuscation_level=None,
    )
    rendered = RenderedSkill(
        spec=spec,
        filename="claude_mal_A01_001.md",
        content_bytes=b"---\nname: test\n---\n\nstub\n",
        format_extension=".md",
        sources=("test",),
    )

    writer = SkillWriter(safe_output_root, project_root=project_root)

    # Patch tempfile.NamedTemporaryFile stat to simulate a cross-fs device mismatch.
    # Per §7.4 step 10: st_dev mismatch → raise OSError before write.
    real_stat = os.stat

    def fake_stat(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        p = str(path)
        if p.endswith(".tmp") or "/tmp/" in p or "/.tmp" in p:

            class _FakeStat:
                def __init__(self, real):
                    for attr in dir(real):
                        if not attr.startswith("_"):
                            try:
                                setattr(self, attr, getattr(real, attr))
                            except (AttributeError, TypeError):
                                pass
                    self.st_dev = real.st_dev + 9999  # force mismatch

            return _FakeStat(result)
        return result

    with mock.patch("benchmarks.generator.writer.os.stat", side_effect=fake_stat):
        with pytest.raises(OSError, match="same-fs"):
            writer.write(rendered)


# ---------------------------------------------------------------------------
# Test 16-17 — enforce_table_11 (LLD-01 §6.12 + §7.11)
# ---------------------------------------------------------------------------


def test_enforce_table_11_raises_on_count_mismatch():
    """§6.12 + §7.11: deliberately wrong count → DistributionMismatchError."""
    from benchmarks.generator.core import ManifestEntry
    from benchmarks.generator.enforce import enforce_table_11
    from benchmarks.generator.exceptions import DistributionMismatchError

    # Build ONE entry labeled claude/A1; Table 11 expects 10 — must fail.
    entries = [
        ManifestEntry(
            skill_id="claude_mal_A01_001",
            format="claude",
            is_malicious=True,
            attack_type="A1",
            parent_class="c1_DATA_EXFILTRATION",
            benign_category=None,
            source_attribution=("test",),
            obfuscation_level=None,
            filename="claude_mal_A01_001.md",
            path="skills/claude/malicious/claude_mal_A01_001.md",
            sha256="0" * 64,
        )
    ]
    with pytest.raises(DistributionMismatchError):
        enforce_table_11(entries)


def test_enforce_table_11_passes_on_exact_distribution():
    """§7.11: entries matching TABLE_11_DISTRIBUTION exactly → returns None.

    Builds a synthetic 540-entry list per the canonical counts. No file I/O.
    """
    from benchmarks.generator.config import BENIGN_CATEGORIES, TABLE_11_DISTRIBUTION
    from benchmarks.generator.core import ManifestEntry
    from benchmarks.generator.enforce import enforce_table_11

    entries: list[ManifestEntry] = []
    for (fmt, atype), count in TABLE_11_DISTRIBUTION.items():
        for i in range(1, count + 1):
            if atype == "benign":
                # 90 benigns per format; distribute evenly across 5 categories → 18 each
                cat = BENIGN_CATEGORIES[(i - 1) // 18]
                entries.append(
                    ManifestEntry(
                        skill_id=f"{fmt}_ben_cat{BENIGN_CATEGORIES.index(cat)+1}_{i:03d}",
                        format=fmt,
                        is_malicious=False,
                        attack_type="benign",
                        parent_class="benign",
                        benign_category=cat,
                        source_attribution=("test",),
                        obfuscation_level=None,
                        filename=f"{fmt}_ben_{i:03d}.md",
                        path=f"skills/{fmt}/benign/{fmt}_ben_{i:03d}.md",
                        sha256="0" * 64,
                    )
                )
            else:
                entries.append(
                    ManifestEntry(
                        skill_id=f"{fmt}_mal_{atype}_{i:03d}",
                        format=fmt,
                        is_malicious=True,
                        attack_type=atype,
                        parent_class="c1_DATA_EXFILTRATION",
                        benign_category=None,
                        source_attribution=("test",),
                        obfuscation_level=None,
                        filename=f"{fmt}_mal_{atype}_{i:03d}.md",
                        path=f"skills/{fmt}/malicious/{fmt}_mal_{atype}_{i:03d}.md",
                        sha256="0" * 64,
                    )
                )

    assert len(entries) == 540, f"synthetic builder produced {len(entries)} entries, expected 540"
    # Exact match — must pass (returns None)
    result = enforce_table_11(entries)
    assert result is None


# ---------------------------------------------------------------------------
# Test 18 — Integration: empty-registries byte-identical run
# ---------------------------------------------------------------------------


def test_benchmark_generator_empty_registries_produces_empty_byte_identical_manifest(
    constructor_kwargs, project_root
):
    """§7.10 bones integration: empty registries → empty manifest, two runs byte-identical.

    Uses the test-only `_permit_empty_registries=True` hatch so Table 11 enforcement
    is skipped and _generation_order yields zero specs. Exercises the full run()
    scaffolding (preflight → safe-root → manifest write → return GenerationReport)
    without needing AttackPattern or BenignCategory realizations (those are T2/T3).

    INV-7 + INV-20: two runs with identical inputs produce byte-identical manifest
    content hash and byte-identical entries[] serialization.
    """
    from benchmarks.generator.core import BenchmarkGenerator

    # Run A
    kwargs_a = dict(constructor_kwargs)
    out_a = kwargs_a["output_root"]
    gen_a = BenchmarkGenerator(
        attack_registry={},
        benign_registry={},
        attack_type_to_class={},
        _permit_empty_registries=True,
        **kwargs_a,
    )
    report_a = gen_a.run()

    # Run B — separate output_root under project_root
    scratch = project_root / ".skfval-tmp"
    out_b = scratch / f"{out_a.name}_b"
    out_b.mkdir()
    kwargs_b = dict(kwargs_a)
    kwargs_b["output_root"] = out_b
    gen_b = BenchmarkGenerator(
        attack_registry={},
        benign_registry={},
        attack_type_to_class={},
        _permit_empty_registries=True,
        **kwargs_b,
    )
    report_b = gen_b.run()

    # Zero entries
    assert report_a.total_skills == 0
    assert report_b.total_skills == 0

    # Byte-identical manifest_content_sha256 (entries-only, independent of run_metadata)
    assert report_a.manifest_content_sha256 == report_b.manifest_content_sha256, (
        "Two empty-registry runs must produce identical manifest_content_sha256"
    )

    # Manifest files exist and entries[] byte-identical
    manifest_a = out_a / "manifest.json"
    manifest_b = out_b / "manifest.json"
    assert manifest_a.exists()
    assert manifest_b.exists()
    mf_a = json.loads(manifest_a.read_bytes())
    mf_b = json.loads(manifest_b.read_bytes())
    assert mf_a["entries"] == mf_b["entries"] == []
    assert mf_a["manifest_content_sha256"] == mf_b["manifest_content_sha256"]
