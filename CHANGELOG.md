# Changelog

All notable changes to SkillFortify are documented here.

This project follows [Semantic Versioning](https://semver.org/).

### [Unreleased]
- **License:** Changed from MIT to Elastic-2.0 to protect research IP

## [0.5.0] - 2026-08-03

### Added
- Skill discovery across every path the runtimes load from: personal, project,
  plugin, and nested package `.claude/skills/`, plus legacy `.claude/commands/`
  and `.openclaw/skills/`. Symlinked skills are followed and de-duplicated on
  their resolved path.
- MCP configuration discovery across all client surfaces, including per-project
  server maps and TOML configs.
- Declared tool grants (`allowed-tools` / `disallowed-tools`) are read as
  capabilities and checked against inferred behaviour.
- Pattern coverage for encoded payloads, reverse shells, interpreter-based
  execution, indirect command construction, DNS-based exfiltration, and
  prompt-injection phrasing, with Unicode normalisation applied before
  matching.
- Redirect revalidation, public-address checks, and response size caps on
  registry fetches.
- Tree-wide integrity hashing over a skill directory rather than `SKILL.md`
  alone.
- `benchmarks/results/` — per-specimen scan records published alongside the
  aggregate summary.
- `benchmarks.metrics` entry point for scoring a scanner against the corpus.
- `benchmarks/metrics/leakage.py` — enumerates structural features of the
  corpus and fails the build if any predicts a specimen's label.

### Changed
- Trust levels require evidence matching their name; a level asserting review
  is not reachable from provenance signals alone.
- Inline interpreter invocations (`python -c`, `node -e`) are graded by what
  the inline program does rather than rated CRITICAL on sight.
- Environment-variable detection requires the underscore convention, so
  capitalised words in prose no longer register as variable references.
- Benchmark specimens are laid out as installable skills — `SKILL.md` under
  each runtime's load path, `.mcp.json` for MCP — with both classes emitted
  through one shared code path.
- Attack type names are written by the generator from the seed modules, so
  documentation and corpus cannot disagree.
- Benchmark metrics are computed per specimen, one scan per prediction.

### Fixed
- `RegistryScanError`, referenced by the registry client, is now defined.
- Corrected the MCP config paths and IDE registry entries used for discovery.

## [0.4.4] - 2026-04-22

### Added
- `AttackType` enum (A1..A13) exposing per-attack-type classification alongside the existing six formal attack classes (paper §8.1 + Appendix B.1).
- `ATTACK_TYPE_TO_CLASS` mapping from concrete attack types to parent formal classes (paper §3.2).
- `AttackClass.is_registry_dependent()` helper identifying classes requiring external registry observability (TYPOSQUATTING, DEPENDENCY_CONFUSION, NAMESPACE_SQUATTING).
- `attack_type` field on `Finding` and `attack_type` key in JSON scan output, enabling per-type benchmark evaluation.
- Pattern catalog entries now carry the `AttackType` that matching findings emit.

## [0.3.2] - 2026-03-04

### Added
- arXiv paper reference (arXiv:2603.00195) in package metadata and documentation

## [0.3.0] - 2026-03-01

### Added
- Expanded framework support to cover all major agent ecosystems
- System-wide scan mode for comprehensive security assessment
- Interactive HTML security report with filtering and export
- New CLI commands for framework listing and report generation
- Marketplace security scanning capabilities

### Changed
- `skillfortify scan` now works without arguments for broader coverage

## [0.2.0] - 2026-02-26

### Added
- LangChain tools format support (BaseTool subclasses, @tool decorators)
- CrewAI tools format support (crew.yaml definitions, tool classes)
- AutoGen tools format support (register_for_llm, function schemas)
- Six agent frameworks now supported (up from three)
- 69 new parser tests (675 total)

## [0.1.0] - 2026-02-26

### Added
- Five CLI commands: scan, verify, lock, trust, sbom
- Formal threat model with capability-based analysis
- Constraint-based dependency resolution with lockfile generation
- Trust score computation with propagation through dependency chains
- CycloneDX 1.6 Agent Skill Bill of Materials (ASBOM) generation
- Support for Claude Code, MCP, and OpenClaw skill formats
- 562 automated tests with property-based verification
