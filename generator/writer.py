"""Atomic writers for skill files + manifest + taxonomy (LLD-01 §6.8-§6.10, §7.4, §7.12).

Importing `os` at module level so tests may monkey-patch
`benchmarks.generator.writer.os.stat` to simulate cross-fs scenarios (§7.4 F-C-24).
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from .config import TABLE_11_DISTRIBUTION
from .exceptions import (
    ForbiddenWordError,
    ManifestIntegrityError,
    UnsafeOutputRootError,
)
from .hashing import sha256_lf


# -----------------------------------------------------------------------------
# SkillWriter
# -----------------------------------------------------------------------------


class SkillWriter:
    """Atomic per-skill file writer with same-fs tempfile + os.replace (§7.4)."""

    def __init__(self, output_root: Path, *, project_root: Path) -> None:
        self._output_root = Path(output_root)
        self._project_root = Path(project_root)

    def write(self, rendered) -> Path:  # noqa: ANN001 (RenderedSkill imported in core)
        spec = rendered.spec
        content_bytes = rendered.content_bytes

        # Defensive forbidden-word scan on content (§7.4 step 1 calls out).
        _forbidden_words_check(content_bytes)

        subdir = "malicious" if spec.is_malicious else "benign"
        target_dir = self._output_root / "skills" / spec.format / subdir
        final_path = target_dir / rendered.filename

        # Relative-to-output-root check at POSIX-string level (pre-exists).
        final_str = str(final_path)
        root_str = str(self._output_root)
        if not final_str.startswith(root_str):
            raise UnsafeOutputRootError(
                final_path,
                "escape_output_root",
                f"{final_path} escapes output_root={self._output_root}",
            )

        os.makedirs(final_path.parent, mode=0o755, exist_ok=True)

        # F-C-24: enforce same-filesystem tempfile.
        target_stat = os.stat(final_path.parent)
        tmp = tempfile.NamedTemporaryFile(
            dir=str(final_path.parent),
            prefix=final_path.name + ".",
            suffix=".tmp",
            delete=False,
        )
        tmp_name = tmp.name
        try:
            tmp_stat = os.stat(tmp_name)
            if tmp_stat.st_dev != target_stat.st_dev:
                tmp.close()
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise OSError(
                    "atomic write requires same-fs tempfile: dev mismatch"
                )

            tmp.write(content_bytes)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp.close()
            os.chmod(tmp_name, 0o644)
            os.replace(tmp_name, final_path)
        except BaseException:
            try:
                tmp.close()
            except Exception:
                pass
            if os.path.exists(tmp_name):
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
            raise

        # Symlink-escape guard post-rename.
        resolved_final = final_path.resolve(strict=True)
        resolved_root = self._output_root.resolve(strict=False)
        try:
            resolved_final.relative_to(resolved_root)
        except ValueError:
            raise UnsafeOutputRootError(
                final_path,
                "symlink_escape",
                f"symlink escape: {final_path}",
            )

        # F-C-29 symmetric post-write re-hash.
        disk_bytes = final_path.read_bytes()
        disk_hash = sha256_lf(disk_bytes)
        mem_hash = sha256_lf(content_bytes)
        if disk_hash != mem_hash:
            raise ManifestIntegrityError(
                f"post_write_hash_mismatch: disk={disk_hash} mem={mem_hash} "
                f"path={final_path}"
            )
        return final_path


def _forbidden_words_check(content: bytes | str) -> None:
    """Case-insensitive grep for FORBIDDEN_WORDS. Raise on any hit (§5.5)."""
    from .config import FORBIDDEN_WORDS

    if isinstance(content, bytes):
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            text = ""
    else:
        text = content
    hay = text.lower()
    for word in FORBIDDEN_WORDS:
        if word.lower() in hay:
            raise ForbiddenWordError(f"forbidden word detected: {word!r}")


# -----------------------------------------------------------------------------
# ManifestWriter
# -----------------------------------------------------------------------------


def _canonical_json_bytes(obj: object) -> bytes:
    """Canonical JSON serialization per §7.5: insertion-order, UTF-8, LF, trailing LF."""
    body = json.dumps(
        obj,
        indent=2,
        sort_keys=False,
        ensure_ascii=False,
        separators=(",", ": "),
        allow_nan=False,
    )
    body = body.replace("\r\n", "\n").replace("\r", "\n")
    body = "\n".join(line.rstrip() for line in body.split("\n"))
    if not body.endswith("\n"):
        body = body + "\n"
    enc = body.encode("utf-8")
    if enc.startswith(b"\xef\xbb\xbf"):
        enc = enc[3:]
    return enc


def _canonical_echo_table_11() -> list[dict]:
    """Echo TABLE_11_DISTRIBUTION as a JSON-safe ordered list of entries."""
    return [
        {"format": fmt, "attack_type": atype, "count": count}
        for (fmt, atype), count in TABLE_11_DISTRIBUTION.items()
    ]


class ManifestWriter:
    """Writes manifest.json with entries[], manifest_content_sha256, run_metadata (§7.12)."""

    def write(
        self,
        output_root: Path,
        entries: Sequence,
        run_metadata,
    ) -> tuple[Path, str]:
        # Step 1: serialize entries alone (list of dicts) in canonical JSON.
        entries_list = [asdict(e) for e in entries]
        entries_bytes = _canonical_json_bytes(entries_list)
        manifest_content_sha256 = sha256_lf(entries_bytes)

        # Step 5+6: build the top-level object (insertion-ordered dict is fine
        # on Py3.7+; asdict(run_metadata) preserves field order).
        top_level = {
            "schema_version": "1.0",
            "paper_doi": "10.48550/arXiv.2603.00195",
            "paper_section": "Appendix B",
            "seed": 42,
            "total_count": len(entries),
            "table_11_distribution": _canonical_echo_table_11(),
            "entries": entries_list,
            "manifest_content_sha256": manifest_content_sha256,
            "run_metadata": asdict(run_metadata),
        }
        full_bytes = _canonical_json_bytes(top_level)

        # Forbidden-word scan on the full serialization (including run_metadata).
        _forbidden_words_check(full_bytes)

        # Write atomically.
        manifest_path = Path(output_root) / "manifest.json"
        _atomic_write_bytes(manifest_path, full_bytes)
        return manifest_path, manifest_content_sha256


# -----------------------------------------------------------------------------
# TaxonomyWriter
# -----------------------------------------------------------------------------


class TaxonomyWriter:
    """Writes attack_taxonomy.json (§6.10)."""

    def write(self, output_root: Path, taxonomy) -> Path:
        doc = {
            "schema_version": taxonomy.schema_version,
            "paper_section": taxonomy.paper_section,
            "formal_classes": dict(taxonomy.formal_classes),
            "attack_types": dict(taxonomy.attack_types),
            "benign_categories": list(taxonomy.benign_categories),
        }
        enc = _canonical_json_bytes(doc)
        _forbidden_words_check(enc)
        path = Path(output_root) / "attack_taxonomy.json"
        _atomic_write_bytes(path, enc)
        return path


# -----------------------------------------------------------------------------
# Atomic byte writer (used by Manifest + Taxonomy)
# -----------------------------------------------------------------------------


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Atomic write via same-dir NamedTemporaryFile + os.replace."""
    target_dir = path.parent
    os.makedirs(target_dir, mode=0o755, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        dir=str(target_dir),
        prefix=path.name + ".",
        suffix=".tmp",
        delete=False,
    )
    tmp_name = tmp.name
    try:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp.close()
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            tmp.close()
        except Exception:
            pass
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise
