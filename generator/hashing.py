"""LF-normalized sha256 primitive (LLD-01 §6.13, F-C-29 symmetric)."""

from __future__ import annotations

import hashlib


def sha256_lf(raw: bytes) -> str:
    """Return sha256 hexdigest of CRLF/CR→LF normalized bytes.

    Per LLD-01 §6.13: normalize raw by replacing CRLF with LF first, then
    replacing any remaining lone CR with LF, then hash. DOES NOT add or strip
    trailing LF. 64 lowercase hex chars.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError(f"sha256_lf requires bytes, got {type(raw).__name__}")
    # Order matters: replace CRLF first to avoid double-mapping, then lone CR.
    normalized = bytes(raw).replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(normalized).hexdigest()
