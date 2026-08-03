"""Canonical constants for benchmarks.generator (LLD-01 §5).

All constants are module-level Final[...]. No factory, no mutable default,
no env-var overrides at import time. Per F-C-37, this module contains ZERO
os.environ references.
"""

from __future__ import annotations

from typing import Final, Mapping

# §5.1 Seed
SEED: Final[int] = 42

# §5.2 Formats and extensions
FORMATS: Final[tuple[str, str, str]] = ("claude", "mcp", "openclaw")

FORMAT_EXTENSIONS: Final[Mapping[str, str]] = {
    "claude": ".md",
    "mcp": ".json",
    "openclaw": ".yaml",
}

# §5.3 Benign categories
BENIGN_CATEGORIES: Final[tuple[str, str, str, str, str]] = (
    "file_management",
    "data_transformation",
    "api_integration",
    "development_tooling",
    "system_information",
)

# §5.4 Table 11 — verbatim from synthesis §3.1
TABLE_11_DISTRIBUTION: Final[Mapping[tuple[str, str], int]] = {
    ("claude", "A1"): 10, ("mcp", "A1"): 10, ("openclaw", "A1"): 10,
    ("claude", "A2"): 6,  ("mcp", "A2"): 6,  ("openclaw", "A2"): 6,
    ("claude", "A3"): 10, ("mcp", "A3"): 10, ("openclaw", "A3"): 10,
    ("claude", "A4"): 10, ("mcp", "A4"): 10, ("openclaw", "A4"): 10,
    ("claude", "A5"): 6,  ("mcp", "A5"): 6,  ("openclaw", "A5"): 6,
    ("claude", "A6"): 6,  ("mcp", "A6"): 6,  ("openclaw", "A6"): 6,
    ("claude", "A7"): 8,  ("mcp", "A7"): 8,  ("openclaw", "A7"): 8,
    ("claude", "A8"): 8,  ("mcp", "A8"): 8,  ("openclaw", "A8"): 8,
    ("claude", "A9"): 8,  ("mcp", "A9"): 8,  ("openclaw", "A9"): 8,
    ("claude", "A10"): 4, ("mcp", "A10"): 4, ("openclaw", "A10"): 4,
    ("claude", "A11"): 4, ("mcp", "A11"): 2, ("openclaw", "A11"): 2,
    ("claude", "A12"): 2, ("mcp", "A12"): 4, ("openclaw", "A12"): 2,
    ("claude", "A13"): 8, ("mcp", "A13"): 8, ("openclaw", "A13"): 10,
    ("claude", "benign"): 90, ("mcp", "benign"): 90, ("openclaw", "benign"): 90,
}

# Skill names, shared by both classes.
#
# Names are drawn from one pool so that the name cannot separate the classes.
# A corpus whose malicious and benign names come from disjoint vocabularies is
# classifiable from a lookup table alone, and a scanner measured against it
# posts a score without reading a single skill. Marketplace malware also
# impersonates useful tools rather than announcing itself, so one shared
# vocabulary is the more faithful choice as well as the sound one.
BENIGN_NAME_POOLS: Final[Mapping[str, tuple[str, ...]]] = {
    "file_management": (
        "text-file-deduper", "dir-tree-summarizer", "yaml-merger",
        "csv-row-counter", "file-hash-report", "json-lint-helper",
        "path-normalizer", "file-size-reporter", "log-file-rotator",
        "config-file-validator", "archive-extractor", "temp-dir-cleaner",
    ),
    "data_transformation": (
        "csv-to-json-converter", "yaml-to-json-bridge", "xml-pretty-printer",
        "json-formatter", "csv-to-tsv-converter", "base-converter",
        "tsv-normalizer", "markdown-table-formatter", "ini-to-yaml-bridge",
        "toml-to-json-converter", "ndjson-splitter", "jsonl-merger",
    ),
    "api_integration": (
        "pypi-version-probe", "github-issue-summarizer", "npm-meta-fetch",
        "docs-python-link-check", "github-repo-stats", "pypi-download-counter",
        "npm-dep-tree-viewer", "github-release-checker", "pypi-license-scanner",
        "npm-audit-reporter", "github-star-tracker", "registry-health-check",
    ),
    "development_tooling": (
        "pytest-flake-reporter", "eslint-rule-counter", "ruff-preset-applier",
        "coverage-line-annotator", "mypy-stub-generator", "black-format-checker",
        "isort-import-sorter", "bandit-security-scanner", "pylint-score-tracker",
        "flake8-config-helper", "tox-env-lister", "pre-commit-hook-runner",
    ),
    "system_information": (
        "uptime-reporter", "disk-usage-summary", "kernel-version-check",
        "free-memory-report", "cpu-info-collector", "hostname-resolver",
        "load-average-monitor", "swap-usage-checker", "os-release-reader",
        "network-iface-lister", "process-count-reporter", "env-path-inspector",
    ),
}

#: Every skill name in the corpus, in a stable order.
SHARED_NAME_POOL: Final[tuple[str, ...]] = tuple(
    sorted({name for pool in BENIGN_NAME_POOLS.values() for name in pool})
)

#: Publisher strings. Both classes draw from this pool, so a claim of being
#: verified is a signal the analyser must weigh rather than a label giveaway.
AUTHOR_POOL: Final[tuple[str, ...]] = (
    "verified-publisher",
    "community",
    "internal-tools",
    "opensource-maintainer",
)

#: Attack types whose skill name *is* the attack, and which therefore keep the
#: name their seed chose. Detecting these names is the scanner's job.
NAME_BEARING_ATTACKS: Final[frozenset[str]] = frozenset({"A11"})

# §5.5 Forbidden words (case-insensitive grep targets)
FORBIDDEN_WORDS: Final[tuple[str, ...]] = (
    "regenerated", "regeneration", "regen",
    "recreated", "recreation",
    "restored", "restoring", "restoration",
    "rebuilt", "rebuilding", "rebuild",
    "lost", "loss", "incident",
    "v2", "version 2",
    "delayed", "overdue", "behind schedule",
    "apologize", "apologies", "sorry",
    "finally available", "now finally", "at last",
    "reconstruction", "reconstructed",
)

# §5.6 Output root default + parser rule
OUTPUT_ROOT_DEFAULT: Final[str] = "benchmarks"
PARSER_ROUNDTRIP_REQUIRED: Final[bool] = True

# §5.8 Dangerous ancestor paths
DANGEROUS_ANCESTOR_PATHS: Final[tuple[str, ...]] = (
    "/root",
    "/etc", "/var", "/usr", "/bin", "/sbin", "/opt",
    "/Applications", "/System", "/Library",
    "/private/etc", "/private/var",
    ".ssh", ".aws", ".gnupg", ".kube",
    "Documents", "Downloads", "Desktop",
)

# Home-relative components among DANGEROUS_ANCESTOR_PATHS
DANGEROUS_HOME_COMPONENTS: Final[tuple[str, ...]] = (
    ".ssh", ".aws", ".gnupg", ".kube",
    "Documents", "Downloads", "Desktop",
)

# Absolute dangerous prefixes (the ones starting with "/")
DANGEROUS_ABS_PREFIXES: Final[tuple[str, ...]] = tuple(
    p for p in DANGEROUS_ANCESTOR_PATHS if p.startswith("/")
)
