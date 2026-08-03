"""Three-phase static analysis engine for agent skill security.

This module implements the ``StaticAnalyzer`` class which orchestrates the
three analysis phases:

1. **Capability Inference** -- abstract interpretation of skill content to
   infer required capabilities (network, shell, filesystem, environment).
2. **Dangerous Pattern Detection** -- matching skill content against known
   threat patterns from ClawHavoc, MalTool, and "Agent Skills in the Wild".
3. **Capability Violation Check** -- comparing inferred capabilities against
   declared capabilities to enforce the Principle of Least Authority (POLA).

References
----------
.. [DV66] Dennis & Van Horn (1966). Capability model foundations.
.. [Mil06] Miller (2006). Object-capability model and POLA.
"""

from __future__ import annotations

from skillfortify.core.analyzer.models import AnalysisResult, Finding, Severity
from skillfortify.core.analyzer.patterns import (
    _BASE64_PATTERN,
    _DANGEROUS_CODE_PATTERNS,
    _DANGEROUS_SHELL_PATTERNS,
    _FILE_READ_PATTERNS,
    _FILE_WRITE_PATTERNS,
    _POST_PATTERNS,
    _PROMPT_INJECTION_PATTERNS,
    _is_safe_url,
    _is_sensitive_env_var,
    normalize_for_matching,
)
from skillfortify.core.capabilities import AccessLevel, Capability, CapabilitySet
from skillfortify.core.threat_model.taxonomy import AttackType
from skillfortify.parsers.base import ParsedSkill

# ---------------------------------------------------------------------------
# Agent tool names -> capability grants
# ---------------------------------------------------------------------------

# Frontmatter such as Claude Code's `allowed-tools: Bash, Write` declares
# authority in tool vocabulary rather than resource vocabulary; this table
# translates it so least-privilege checking can act on it.
_TOOL_CAPABILITIES: dict[str, tuple[tuple[str, AccessLevel], ...]] = {
    "bash": (("shell", AccessLevel.ADMIN),),
    "shell": (("shell", AccessLevel.ADMIN),),
    "run_terminal_command": (("shell", AccessLevel.ADMIN),),
    "read": (("filesystem", AccessLevel.READ),),
    "glob": (("filesystem", AccessLevel.READ),),
    "grep": (("filesystem", AccessLevel.READ),),
    "list_dir": (("filesystem", AccessLevel.READ),),
    "write": (("filesystem", AccessLevel.WRITE),),
    "edit": (("filesystem", AccessLevel.WRITE),),
    "notebookedit": (("filesystem", AccessLevel.WRITE),),
    "search_replace": (("filesystem", AccessLevel.WRITE),),
    "webfetch": (("network", AccessLevel.READ),),
    "websearch": (("network", AccessLevel.READ),),
    "open_page": (("network", AccessLevel.READ),),
    "task": (("skill_invoke", AccessLevel.WRITE),),
    "agent": (("skill_invoke", AccessLevel.WRITE),),
    "skill": (("skill_invoke", AccessLevel.WRITE),),
}

# Number of ADMIN-level resources at which a declaration stops constraining
# anything and becomes a finding in its own right.
_OVER_DECLARATION_THRESHOLD = 3


def _excerpt(original: str, pattern, probe: str, window: int = 120) -> str:
    """Return the matching region of ``original`` for use as finding evidence.

    Matching runs against a normalised ``probe`` while evidence quotes the
    text the skill actually contains, so match offsets are applied back to the
    original string. Normalisation only deletes or substitutes single
    codepoints, keeping offsets usable for a human-readable excerpt.
    """
    match = pattern.search(probe)
    if match is None:
        return original[:window]
    start = max(0, match.start() - 20)
    end = min(len(original), match.end() + 20)
    excerpt = original[start:end].strip()
    return excerpt if excerpt else original[:window]


class StaticAnalyzer:
    """Three-phase static analyzer for agent skill security.

    The analyzer takes a ``ParsedSkill`` and returns an ``AnalysisResult``
    containing all security findings. Analysis proceeds in three sequential
    phases: capability inference, dangerous pattern detection, and capability
    violation checking.

    The analyzer is stateless -- each ``analyze()`` call is independent.
    This enables safe concurrent analysis of multiple skills.

    Usage::

        analyzer = StaticAnalyzer()
        result = analyzer.analyze(parsed_skill)
        if not result.is_safe:
            for finding in result.findings:
                print(f"[{finding.severity.name}] {finding.message}")
    """

    def analyze(self, skill: ParsedSkill) -> AnalysisResult:
        """Analyze a parsed skill and return all security findings.

        Three phases run sequentially:
          1. Capability inference from static patterns.
          2. Dangerous pattern matching against known threats.
          3. Capability violation check (inferred vs declared).

        Args:
            skill: The parsed skill to analyze.

        Returns:
            An ``AnalysisResult`` with all findings, safety verdict, and
            inferred capabilities.
        """
        findings: list[Finding] = []

        # Phase 1: Capability inference
        inferred = self._infer_capabilities(skill)

        # Phase 2: Dangerous pattern detection
        findings.extend(self._detect_dangerous_patterns(skill))

        # Phase 3: Capability violation check
        # POLA compares a skill's DECLARED authority against its inferred
        # behaviour, so it applies only when the skill makes a claim. A skill
        # declaring nothing has made no claim to violate; it remains covered by
        # dangerous-pattern detection. Over-declaration and unparsable
        # declarations are checked in _check_capability_violations.
        if skill.declared_capabilities:
            findings.extend(self._check_capability_violations(skill, inferred))

        is_safe = len(findings) == 0

        return AnalysisResult(
            skill_name=skill.name,
            is_safe=is_safe,
            findings=findings,
            inferred_capabilities=inferred,
        )

    # -- Phase 1: Capability Inference (Abstract Interpretation) --

    def _infer_capabilities(self, skill: ParsedSkill) -> CapabilitySet:
        """Infer the capability set a skill actually needs from its content.

        This is a conservative over-approximation (sound abstract interpretation):
        if a pattern suggests a capability, we include it. False positives are
        acceptable; false negatives are not.

        Returns:
            A ``CapabilitySet`` representing inferred capabilities.
        """
        caps = CapabilitySet()

        # URLs present -> network capability
        if skill.urls:
            # Default to READ; upgrade to WRITE if POST-like patterns found
            network_level = AccessLevel.READ
            # Check shell commands for POST/PUT/PATCH/DELETE patterns
            combined_shell = " ".join(skill.shell_commands)
            for pat in _POST_PATTERNS:
                if pat.search(combined_shell):
                    network_level = AccessLevel.WRITE
                    break
            caps.add(Capability("network", network_level))

        # Shell commands present -> shell:WRITE
        if skill.shell_commands:
            caps.add(Capability("shell", AccessLevel.WRITE))

        # Environment variable references -> environment:READ
        if skill.env_vars_referenced:
            caps.add(Capability("environment", AccessLevel.READ))

        # File operation patterns in instructions -> filesystem capability
        combined_text = f"{skill.instructions} {skill.description}"
        has_file_write = any(pat.search(combined_text) for pat in _FILE_WRITE_PATTERNS)
        has_file_read = any(pat.search(combined_text) for pat in _FILE_READ_PATTERNS)

        if has_file_write:
            caps.add(Capability("filesystem", AccessLevel.WRITE))
        elif has_file_read:
            caps.add(Capability("filesystem", AccessLevel.READ))

        return caps

    # -- Phase 2: Dangerous Pattern Detection --

    def _detect_dangerous_patterns(self, skill: ParsedSkill) -> list[Finding]:
        """Detect known-dangerous patterns in the skill's content.

        Checks shell commands, code blocks, URLs, and environment variable
        references against a catalog of threat patterns.

        Returns:
            List of findings from pattern matching.
        """
        findings: list[Finding] = []

        # 2a: Shell command patterns. Matching runs against a normalised copy
        # (zero-width codepoints stripped, homoglyphs folded); evidence quotes
        # the original so reports show the skill's actual content.
        for cmd in skill.shell_commands:
            probe = normalize_for_matching(cmd)
            for pattern, severity, attack_class, message, attack_type in _DANGEROUS_SHELL_PATTERNS:
                if pattern.search(probe):
                    findings.append(
                        Finding(
                            skill_name=skill.name,
                            severity=severity,
                            message=message,
                            attack_class=attack_class,
                            finding_type="pattern_match",
                            evidence=cmd,
                            attack_type=attack_type,
                        )
                    )

        # 2b: Code block patterns. Both catalogs apply to every fenced block
        # regardless of language tag, since a ```python or ```console fence is
        # as executable as ```bash.
        for block in skill.code_blocks:
            probe = normalize_for_matching(block)
            for pattern, severity, attack_class, message, attack_type in (
                *_DANGEROUS_CODE_PATTERNS,
                *_DANGEROUS_SHELL_PATTERNS,
            ):
                if pattern.search(probe):
                    findings.append(
                        Finding(
                            skill_name=skill.name,
                            severity=severity,
                            message=message,
                            attack_class=attack_class,
                            finding_type="pattern_match",
                            evidence=block,
                            attack_type=attack_type,
                        )
                    )

        # 2b-ii: Narrative instruction text.
        # A skill's instructions are read and acted on by a model, so prose is
        # an execution surface in its own right. Two classes matter here:
        # shell commands that appear only in prose (never fenced, so the parser
        # never extracts them), and prompt-injection directives aimed at the
        # agent rather than at a shell.
        instruction_text = skill.instructions or ""
        if instruction_text:
            probe = normalize_for_matching(instruction_text)
            for pattern, severity, attack_class, message, attack_type in (
                *_PROMPT_INJECTION_PATTERNS,
                *_DANGEROUS_SHELL_PATTERNS,
            ):
                if pattern.search(probe):
                    findings.append(
                        Finding(
                            skill_name=skill.name,
                            severity=severity,
                            message=message,
                            attack_class=attack_class,
                            finding_type="pattern_match",
                            evidence=_excerpt(instruction_text, pattern, probe),
                            attack_type=attack_type,
                        )
                    )

        # 2c: External URLs (not in allow-list) -> A1 HTTP exfil
        for url in skill.urls:
            if not _is_safe_url(url):
                findings.append(
                    Finding(
                        skill_name=skill.name,
                        severity=Severity.HIGH,
                        message=f"External URL detected: {url}",
                        attack_class="data_exfiltration",
                        finding_type="pattern_match",
                        evidence=url,
                        attack_type=AttackType.A1,
                    )
                )

        # 2d: Sensitive environment variable access -> A3 credential theft
        for env_var in skill.env_vars_referenced:
            if _is_sensitive_env_var(env_var):
                findings.append(
                    Finding(
                        skill_name=skill.name,
                        severity=Severity.HIGH,
                        message=f"Sensitive environment variable accessed: {env_var}",
                        attack_class="data_exfiltration",
                        finding_type="pattern_match",
                        evidence=env_var,
                        attack_type=AttackType.A3,
                    )
                )

        # 2e: Information flow: base64 encoding + external URL -> A13 encoded/obfuscated
        # This combination suggests data exfiltration via encoding.
        has_base64 = any(_BASE64_PATTERN.search(cmd) for cmd in skill.shell_commands) or any(
            _BASE64_PATTERN.search(block) for block in skill.code_blocks
        )
        has_external_urls = any(not _is_safe_url(url) for url in skill.urls)

        if has_base64 and has_external_urls:
            findings.append(
                Finding(
                    skill_name=skill.name,
                    severity=Severity.CRITICAL,
                    message=(
                        "Information flow concern: base64 encoding combined with "
                        "external network access suggests data exfiltration"
                    ),
                    attack_class="data_exfiltration",
                    finding_type="info_flow",
                    evidence="base64 + external URL",
                    attack_type=AttackType.A13,
                )
            )

        return findings

    # -- Phase 3: Capability Violation Check --

    def _check_capability_violations(
        self, skill: ParsedSkill, inferred: CapabilitySet
    ) -> list[Finding]:
        """Compare inferred capabilities against declared capabilities.

        Each inferred capability that is NOT permitted by the declared set
        is a violation -- the skill needs more authority than it claims.

        Args:
            skill: The parsed skill (for declared_capabilities).
            inferred: The inferred capability set from Phase 1.

        Returns:
            List of capability violation findings.
        """
        # Two declaration vocabularies reach this list: canonical
        # "resource:LEVEL" strings, and agent tool names from frontmatter such
        # as Claude Code's `allowed-tools: Bash, Write`. Both are resolved;
        # anything unrecognised is reported rather than dropped.
        declared = CapabilitySet()
        unparsed: list[str] = []
        for cap_str in skill.declared_capabilities:
            parts = cap_str.split(":", 1)
            if len(parts) == 2:
                resource = parts[0].strip().lower()
                level_str = parts[1].strip().upper()
                try:
                    level = AccessLevel[level_str]
                except KeyError:
                    unparsed.append(cap_str)
                    continue
                declared.add(Capability(resource, level))
                continue

            mapped = _TOOL_CAPABILITIES.get(cap_str.strip().lower())
            if mapped:
                for resource, level in mapped:
                    declared.add(Capability(resource, level))
            else:
                unparsed.append(cap_str)

        # A skill granting itself ADMIN across several resources, or naming a
        # wildcard resource, pre-authorises almost any behaviour and so can
        # never register a violation. The breadth of the declaration is
        # therefore reported as the finding.
        admin_resources = [c.resource for c in declared if c.access >= AccessLevel.ADMIN]
        if "*" in admin_resources or len(admin_resources) >= _OVER_DECLARATION_THRESHOLD:
            findings_prefix = [
                Finding(
                    skill_name=skill.name,
                    severity=Severity.HIGH,
                    message=(
                        "Over-declared authority: ADMIN on "
                        f"{len(admin_resources)} resource(s) pre-authorises almost any "
                        "behaviour, so least-privilege checking cannot constrain this skill"
                    ),
                    attack_class="privilege_escalation",
                    finding_type="capability_violation",
                    evidence=", ".join(sorted(set(admin_resources))),
                    attack_type=AttackType.A6,
                )
            ]
        else:
            findings_prefix = []

        if unparsed:
            findings_prefix.append(
                Finding(
                    skill_name=skill.name,
                    severity=Severity.LOW,
                    message=(
                        "Unrecognised capability declaration(s); these grant nothing "
                        "and are ignored by least-privilege checking"
                    ),
                    attack_class="misconfiguration",
                    finding_type="capability_violation",
                    evidence=", ".join(sorted(set(unparsed))[:8]),
                    attack_type=AttackType.A6,
                )
            )

        # Find violations: inferred capabilities not covered by declared
        violations = inferred.violations_against(declared)

        findings: list[Finding] = list(findings_prefix)
        for violation in violations:
            # Capability-violation heuristic per LLD-04 §8.4:
            # shell / filesystem:WRITE -> A6 privilege escalation;
            # network -> A1 HTTP exfil; else None (ambiguous).
            attack_type: AttackType | None
            resource = violation.resource
            if (
                resource == "shell"
                or resource == "filesystem"
                and violation.access >= AccessLevel.WRITE
            ):
                attack_type = AttackType.A6
            elif resource == "network":
                attack_type = AttackType.A1
            else:
                attack_type = None

            findings.append(
                Finding(
                    skill_name=skill.name,
                    severity=Severity.HIGH,
                    message=(
                        f"Capability violation: skill requires "
                        f"{violation.resource}:{violation.access.name} "
                        f"but only declares up to "
                        f"{_declared_level_str(declared, violation.resource)}"
                    ),
                    attack_class="privilege_escalation",
                    finding_type="capability_violation",
                    evidence=f"inferred={violation.resource}:{violation.access.name}",
                    attack_type=attack_type,
                )
            )

        return findings


def _declared_level_str(declared: CapabilitySet, resource: str) -> str:
    """Get a human-readable string for the declared level of a resource."""
    for cap in declared:
        if cap.resource == resource:
            return f"{cap.resource}:{cap.access.name}"
    return f"{resource}:NONE (undeclared)"
