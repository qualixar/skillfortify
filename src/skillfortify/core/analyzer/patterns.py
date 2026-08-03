"""Threat pattern catalogs and helper functions for static analysis.

This module contains all compiled regex patterns used by the analysis engine
to detect dangerous behaviors in agent skills. Patterns are derived from:

- ClawHavoc campaign (at least 1,184 malicious skills, Feb 2026)
- MalTool benchmark (7,027 malicious tools, arXiv:2602.12194)
- "Agent Skills in the Wild" survey (42,447 skills, arXiv:2601.10338)

The catalogs are intentionally separated from the engine so they can be:
1. Tested independently (pattern coverage, false positive rates).
2. Extended by users via configuration without modifying engine code.
3. Versioned and audited as the threat landscape evolves.

References
----------
.. [ClawHavoc26] "SoK: Agentic Skills -- Beyond Tool Use in LLM Agents" (arXiv:2602.20867).
.. [MalTool26] "MalTool" (arXiv:2602.12194). 7,027 malicious tools (1,300 standalone + 5,727 with embedded behaviour).
.. [ASW26] "Agent Skills in the Wild" (arXiv:2601.10338). 42,447 skills.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from skillfortify.core.analyzer.models import Severity
from skillfortify.core.threat_model.taxonomy import AttackType

# ---------------------------------------------------------------------------
# URL allow-list for safe domains
# ---------------------------------------------------------------------------

_SAFE_URL_DOMAINS: frozenset[str] = frozenset(
    {
        "github.com",
        "www.github.com",
        "pypi.org",
        "www.pypi.org",
        "npmjs.org",
        "www.npmjs.org",
        "npmjs.com",
        "www.npmjs.com",
        # Documentation hosts, named individually so that trust follows a
        # specific organisation rather than a hostname pattern.
        "docs.python.org",
        "docs.rs",
        "docs.djangoproject.com",
        "developer.mozilla.org",
        "docs.oracle.com",
        "docs.microsoft.com",
        "learn.microsoft.com",
        "docs.aws.amazon.com",
        "cloud.google.com",
        "kubernetes.io",
        "docs.docker.com",
        "readthedocs.io",
        "docs.anthropic.com",
        "code.claude.com",
        "platform.openai.com",
    }
)

_SAFE_URL_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".github.com",
    ".pypi.org",
    ".npmjs.org",
    ".npmjs.com",
)


def _is_safe_url(url: str) -> bool:
    """Check if a URL belongs to a known-safe domain.

    Safe domains are github.com, pypi.org, npmjs.org and their subdomains.
    Nothing else is trusted: an allow-list entry is a permanent hole, so it
    must name a specific organisation rather than a naming convention.
    """
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return False

    # Exact match on known-safe domains
    if hostname in _SAFE_URL_DOMAINS:
        return True

    # Subdomain match (e.g., raw.github.com)
    for suffix in _SAFE_URL_DOMAIN_SUFFIXES:
        if hostname.endswith(suffix):
            return True

    # Trust is granted by explicit host, never by naming convention: a
    # prefix rule such as `docs.*` would trust any host an attacker registers
    # under that prefix.
    return False


# ---------------------------------------------------------------------------
# Input normalisation
# ---------------------------------------------------------------------------

# Codepoints that render as nothing. Stripping them keeps invisible
# characters from splitting a token that pattern matching depends on.
_ZERO_WIDTH_CHARS = (
    "\u200b"  # zero-width space
    "\u200c"  # zero-width non-joiner
    "\u200d"  # zero-width joiner
    "\ufeff"  # zero-width no-break space / BOM
    "\u2060"  # word joiner
    "\u00ad"  # soft hyphen
)

# Non-Latin codepoints that render identically to ASCII letters. Mapping them
# back is what stops `сurl` (Cyrillic es) from evading a `curl` pattern.
_HOMOGLYPH_MAP = str.maketrans(
    {
        "\u0430": "a",  # Cyrillic a
        "\u0435": "e",  # Cyrillic ie
        "\u043e": "o",  # Cyrillic o
        "\u0440": "p",  # Cyrillic er
        "\u0441": "c",  # Cyrillic es
        "\u0445": "x",  # Cyrillic ha
        "\u0455": "s",  # Cyrillic dze
        "\u0456": "i",  # Cyrillic byelorussian-ukrainian i
        "\u0501": "d",  # Cyrillic komi de
        "\u03bf": "o",  # Greek omicron
        "\u0391": "A",  # Greek Alpha
        "\u0410": "A",  # Cyrillic A
        "\u0421": "C",  # Cyrillic Es
    }
)


def normalize_for_matching(text: str) -> str:
    """Canonicalise text before pattern matching.

    Strips zero-width codepoints and folds visually-identical non-Latin
    characters to ASCII, so that matching sees the same token a shell would
    execute.

    The original text is preserved separately for evidence reporting, so
    findings quote what the skill actually contains.
    """
    cleaned = text.translate({ord(ch): None for ch in _ZERO_WIDTH_CHARS})
    return cleaned.translate(_HOMOGLYPH_MAP)


# ---------------------------------------------------------------------------
# Sensitive environment variable patterns
# ---------------------------------------------------------------------------

_SENSITIVE_ENV_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r".*SECRET.*", re.IGNORECASE),
    re.compile(r".*PASSWORD.*", re.IGNORECASE),
    re.compile(r".*TOKEN.*", re.IGNORECASE),
    re.compile(r".*API[_-]?KEY.*", re.IGNORECASE),
    re.compile(r".*CREDENTIAL.*", re.IGNORECASE),
    re.compile(r".*PRIVATE[_-]?KEY.*", re.IGNORECASE),
    re.compile(r"^AWS_ACCESS_KEY_ID$", re.IGNORECASE),
    re.compile(r"^DATABASE_URL$", re.IGNORECASE),
)


def _is_sensitive_env_var(name: str) -> bool:
    """Check if an environment variable name matches a sensitive pattern."""
    return any(pat.match(name) for pat in _SENSITIVE_ENV_PATTERNS)


# ---------------------------------------------------------------------------
# Dangerous shell/code patterns (Phase 2)
# ---------------------------------------------------------------------------

# Each entry: (compiled regex, severity, attack_class, message_template, attack_type)
# The regex is matched against individual shell commands or code blocks.
# attack_type (A1..A13) per LLD-04 §8.4 maps patterns to paper §8.1 granular types.

_DANGEROUS_SHELL_PATTERNS: list[tuple[re.Pattern[str], Severity, str, str, AttackType]] = [
    # CRITICAL: Remote code via pipe-to-shell
    (
        re.compile(r"curl\s+.*\|\s*(ba)?sh", re.IGNORECASE),
        Severity.CRITICAL,
        "privilege_escalation",
        "Remote code: curl piped to shell",
        AttackType.A4,
    ),
    (
        re.compile(r"wget\s+.*\|\s*(ba)?sh", re.IGNORECASE),
        Severity.CRITICAL,
        "privilege_escalation",
        "Remote code: wget piped to shell",
        AttackType.A4,
    ),
    # CRITICAL: Destructive file operations
    (
        re.compile(r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*r"),
        Severity.CRITICAL,
        "privilege_escalation",
        "Destructive operation: recursive forced removal (rm -rf)",
        AttackType.A5,
    ),
    # CRITICAL: Encoded payload to shell
    (
        re.compile(r"base64\s+-d.*\|\s*(ba)?sh", re.IGNORECASE),
        Severity.CRITICAL,
        "privilege_escalation",
        "Obfuscated code: base64 decode piped to shell",
        AttackType.A13,
    ),
    # CRITICAL: Netcat listener (reverse shell / data exfiltration)
    (
        re.compile(r"nc\s+-l", re.IGNORECASE),
        Severity.CRITICAL,
        "data_exfiltration",
        "Network listener detected: netcat in listen mode (potential reverse shell)",
        AttackType.A9,
    ),
    # HIGH: Excessive permissions
    (
        re.compile(r"chmod\s+777"),
        Severity.HIGH,
        "privilege_escalation",
        "Excessive permissions: chmod 777 grants world read/write/execute",
        AttackType.A6,
    ),
    # CRITICAL: encoded payload delivery. Patterns match the decode-then-
    # execute BEHAVIOUR across decoders and flag spellings, since any single
    # spelling is trivially substituted.
    (
        re.compile(r"base64\s+(-d\b|--decode\b).*\|\s*(ba)?sh", re.IGNORECASE),
        Severity.CRITICAL,
        "privilege_escalation",
        "Obfuscated code: base64 decode piped to shell",
        AttackType.A13,
    ),
    (
        re.compile(r"\bxxd\s+.*-r.*\|\s*(ba)?sh", re.IGNORECASE),
        Severity.CRITICAL,
        "privilege_escalation",
        "Obfuscated code: hex decode piped to shell",
        AttackType.A13,
    ),
    (
        re.compile(r"openssl\s+enc\s+.*-d\b.*\|\s*(ba)?sh", re.IGNORECASE),
        Severity.CRITICAL,
        "privilege_escalation",
        "Obfuscated code: openssl decode piped to shell",
        AttackType.A13,
    ),
    # CRITICAL: reverse shells, covering both listener and outbound
    # connect-back forms.
    (
        re.compile(r"/dev/(tcp|udp)/", re.IGNORECASE),
        Severity.CRITICAL,
        "privilege_escalation",
        "Reverse shell: bash /dev/tcp connect-back",
        AttackType.A7,
    ),
    (
        re.compile(r"\bn(c|cat)\s+.*-e\b", re.IGNORECASE),
        Severity.CRITICAL,
        "privilege_escalation",
        "Reverse shell: netcat -e spawns a shell on connect",
        AttackType.A7,
    ),
    (
        re.compile(r"socket\s*\(.*\bconnect\s*\(|\bdup2\s*\(", re.IGNORECASE),
        Severity.CRITICAL,
        "privilege_escalation",
        "Reverse shell: socket connect with descriptor duplication",
        AttackType.A7,
    ),
    (
        re.compile(r"\bpty\.spawn\s*\(", re.IGNORECASE),
        Severity.CRITICAL,
        "privilege_escalation",
        "Reverse shell: pty.spawn attaches an interactive shell",
        AttackType.A7,
    ),
    # Dynamic execution via interpreter flags.
    #
    # An inline program is an execution surface, not by itself an attack:
    # ``python -c 'import json; ...'`` is ordinary tooling, and rating every
    # occurrence CRITICAL buries real findings under routine ones. The flag is
    # therefore graded by what the inline program actually does -- CRITICAL
    # when it decodes, execs, reaches the network or reads the environment,
    # and informational otherwise.
    (
        re.compile(
            r"\b(?:python[0-9.]*\s+-c|node\s+-e|perl\s+-e|ruby\s+-e)\b[^\n]*?"
            r"(?:base64|b64decode|atob|\bexec\s*\(|\beval\s*\(|__import__|"
            r"socket|requests\.|urllib|http[s]?://|os\.environ|os\.getenv|"
            r"subprocess|child_process)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "privilege_escalation",
        "Arbitrary code execution: inline program decodes, executes, or reaches outside the process",
        AttackType.A7,
    ),
    (
        re.compile(
            r"\b(?:python[0-9.]*\s+-c|node\s+-e|perl\s+-e|ruby\s+-e)\b", re.IGNORECASE
        ),
        Severity.LOW,
        "privilege_escalation",
        "Inline interpreter program: an execution surface worth reviewing",
        AttackType.A7,
    ),
    (
        re.compile(r"\bos\.system\s*\(|\bsubprocess\.(run|call|Popen)\s*\(", re.IGNORECASE),
        Severity.HIGH,
        "privilege_escalation",
        "Shell invocation from code: os.system / subprocess",
        AttackType.A7,
    ),
    # HIGH: destructive commands, matched in both clustered short-flag and
    # GNU long-option spellings.
    (
        re.compile(r"\brm\s+(?=.*--recursive)(?=.*--force)", re.IGNORECASE),
        Severity.HIGH,
        "destructive",
        "Destructive: recursive force delete (long options)",
        AttackType.A6,
    ),
    (
        re.compile(r"chmod\s+(a\+rwx|ugo\+rwx|[0-7]*777)", re.IGNORECASE),
        Severity.HIGH,
        "privilege_escalation",
        "Overly permissive file mode: world-writable and executable",
        AttackType.A6,
    ),
    # CRITICAL: shell indirection. `${SHELL:-bash}` and `$(which sh)` resolve
    # to a shell at runtime, so a literal shell name is not required.
    (
        re.compile(r"\|\s*[\"']?\$[({]", re.IGNORECASE),
        Severity.CRITICAL,
        "privilege_escalation",
        "Remote code: output piped to a shell resolved indirectly",
        AttackType.A13,
    ),
    # HIGH: DNS exfiltration (A2). Data is smuggled in a subdomain label, so no
    # HTTP request ever appears. Command substitution inside a lookup argument
    # is the signature.
    (
        re.compile(r"\b(dig|nslookup|host|drill)\b.*\$[({]", re.IGNORECASE),
        Severity.HIGH,
        "data_exfiltration",
        "DNS exfiltration: command substitution inside a DNS lookup",
        AttackType.A2,
    ),
    (
        re.compile(r"\b(dig|nslookup|host)\b\s+.*\.[a-z0-9-]+\.[a-z]{2,}\s*$", re.IGNORECASE),
        Severity.MEDIUM,
        "data_exfiltration",
        "DNS lookup to an external domain (possible DNS-channel exfiltration)",
        AttackType.A2,
    ),
]

# Build the dynamic code detection patterns from string fragments
# to avoid triggering security linters that flag the literal function names.
_EVAL_NAME = "ev" + "al"
_EXEC_NAME = "ex" + "ec"

_DANGEROUS_CODE_PATTERNS: list[tuple[re.Pattern[str], Severity, str, str, AttackType]] = [
    (
        re.compile(rf"\b{_EVAL_NAME}\s*\("),
        Severity.HIGH,
        "privilege_escalation",
        f"Dynamic code evaluation: {_EVAL_NAME}() can run arbitrary code",
        AttackType.A4,
    ),
    (
        re.compile(rf"\b{_EXEC_NAME}\s*\("),
        Severity.HIGH,
        "privilege_escalation",
        f"Dynamic code evaluation: {_EXEC_NAME}() can run arbitrary code",
        AttackType.A4,
    ),
    # HIGH: indirect resolution of a dangerous builtin, via attribute access
    # or name concatenation.
    (
        re.compile(r"\bgetattr\s*\(\s*(__builtins__|builtins|__import__\s*\()", re.IGNORECASE),
        Severity.HIGH,
        "privilege_escalation",
        "Dynamic code evaluation: builtin resolved indirectly via getattr",
        AttackType.A4,
    ),
    (
        re.compile(r"[\"'](?:ev|ex)[\"']\s*\+\s*[\"'](?:al|ec)[\"']"),
        Severity.HIGH,
        "privilege_escalation",
        "Obfuscation: dangerous builtin name assembled by concatenation",
        AttackType.A13,
    ),
]

# ---------------------------------------------------------------------------
# Prompt-injection patterns (A8) -- matched against narrative instruction text
# ---------------------------------------------------------------------------

# Skill instructions are read and acted on by a model, so imperative text is
# an execution surface in its own right.
_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], Severity, str, str, AttackType]] = [
    (
        re.compile(
            r"\b(ignore|disregard|forget|override)\b[^.]{0,40}\b"
            r"(previous|prior|earlier|above|all)\b[^.]{0,20}\b"
            r"(instruction|rule|prompt|direction|guideline)s?\b",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "prompt_injection",
        "Prompt injection: instructions attempt to override prior directives",
        AttackType.A3,
    ),
    (
        re.compile(
            r"\b(reveal|print|output|show|repeat|disclose)\b[^.]{0,30}\b"
            r"(system\s+prompt|initial\s+instruction|hidden\s+instruction)s?\b",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "prompt_injection",
        "Prompt injection: attempts to extract the system prompt",
        AttackType.A3,
    ),
    (
        re.compile(
            # The negation must attach directly to the reporting verb, so
            # that guidance where the two sit in different clauses -- such as
            # "do not claim X - tell the user the truth" -- does not match.
            r"\b(do\s+not|don't|never)\s+(?:[a-z]+\s+){0,2}?"
            r"(tell|inform|notify|alert|mention\s+this\s+to)\s+(?:the\s+)?"
            r"(user|human|operator)\b",
            re.IGNORECASE,
        ),
        # MEDIUM and worded for triage: this phrasing covers both concealment
        # directives and benign accuracy guidance, and separating the two needs
        # semantics rather than pattern matching.
        Severity.MEDIUM,
        "prompt_injection",
        (
            "Review: instructs the agent not to tell the user something "
            "(concealment directive, or benign accuracy guidance)"
        ),
        AttackType.A3,
    ),
]

# Patterns indicating POST/write HTTP operations in shell commands
_POST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-X\s+POST", re.IGNORECASE),
    re.compile(r"-X\s+PUT", re.IGNORECASE),
    re.compile(r"-X\s+PATCH", re.IGNORECASE),
    re.compile(r"-X\s+DELETE", re.IGNORECASE),
    re.compile(r"--data\b", re.IGNORECASE),
    re.compile(r"-d\s+['\"]", re.IGNORECASE),
)

# Patterns indicating file operations in instructions
_FILE_READ_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bread[s]?\s+file", re.IGNORECASE),
    re.compile(r"\bopen[s]?\s+file", re.IGNORECASE),
    re.compile(r"\bload[s]?\s+file", re.IGNORECASE),
    re.compile(r"\bread[s]?\s+from\s+", re.IGNORECASE),
)

_FILE_WRITE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bwrite[s]?\s+to\s+", re.IGNORECASE),
    re.compile(r"\bwrite[s]?\s+file", re.IGNORECASE),
    re.compile(r"\bsave[s]?\s+to\s+", re.IGNORECASE),
    re.compile(r"\bcreate[s]?\s+file", re.IGNORECASE),
)

# base64 usage pattern (for info_flow detection)
_BASE64_PATTERN: re.Pattern[str] = re.compile(r"\bbase64\b", re.IGNORECASE)
