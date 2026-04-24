# SkillFortifyBench

A 540-skill, 3-format benchmark for evaluating AI agent skill supply chain security scanners.

## About This Release

This release is a deterministic execution of the benchmark specification in
Appendix B of *Formal Analysis and Supply Chain Security for Agentic AI Skills*
(Bhardwaj 2026, arXiv:2603.00195). All 540 skills are produced byte-identically
via `python -m benchmarks.generator --seed 42` per paper Section B.3 Principle 2. The
novelty of this artifact is limited to engineering reproducibility (Docker pin,
hash-pinned dependencies, SOURCE\_DATE\_EPOCH); conceptual contribution rests in
the paper. See **Citations and Prior Work** below for adjacent benchmarks.

## Overview

SkillFortifyBench provides 540 skills across Claude (`.md`), MCP (`.json`), and
OpenClaw (`.yaml`) formats — 270 malicious (13 attack types, A1-A13) and 270
benign (5 categories) — generated deterministically from seed=42.

SkillFortify is part of the broader effort in AI Reliability Engineering:
building tooling that makes agent ecosystems trustworthy by default.

## Quick Start

```bash
pip install skillfortify
PYTHONHASHSEED=0 python -m benchmarks.generator --output ./benchmark-output --seed 42
```

Or via Docker (recommended for byte-identical reproduction):

```bash
docker run --rm \
    --security-opt seccomp=seccomp-default.json \
    --cap-drop=ALL \
    --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,noexec \
    -v "$(pwd)/results:/bench/results:rw" \
    skillfortify-bench:v1.0.0
```

## Contents

- `skills/claude/` — 180 Claude skills (90 malicious + 90 benign)
- `skills/mcp/` — 180 MCP server configs (90 malicious + 90 benign)
- `skills/openclaw/` — 180 OpenClaw skills (90 malicious + 90 benign)
- `manifest.json` — 540-entry manifest with SHA-256 hashes
- `attack_taxonomy.json` — A1-A13 attack type taxonomy

## Attack Type Distribution (Table 11)

| Type | Claude | MCP | OpenClaw | Total | Description |
|------|-------:|----:|---------:|------:|-------------|
| A1   |     10 |  10 |       10 |    30 | HTTP exfiltration |
| A2   |      6 |   6 |        6 |    18 | DNS exfiltration |
| A3   |     10 |  10 |       10 |    30 | Prompt injection |
| A4   |     10 |  10 |       10 |    30 | Tool poisoning |
| A5   |      6 |   6 |        6 |    18 | Credential theft |
| A6   |      6 |   6 |        6 |    18 | Privilege escalation |
| A7   |      8 |   8 |        8 |    24 | Arbitrary code execution |
| A8   |      8 |   8 |        8 |    24 | Indirect prompt injection |
| A9   |      8 |   8 |        8 |    24 | Shadow tool registration |
| A10  |      4 |   4 |        4 |    12 | Dependency confusion |
| A11  |      4 |   2 |        2 |     8 | Skill squatting |
| A12  |      2 |   4 |        2 |     8 | Typosquatting |
| A13  |      8 |   8 |       10 |    26 | Multi-vector composite |
| **Malicious** | **90** | **90** | **90** | **270** | — |
| Benign |   90 |  90 |       90 |   270 | 5 categories |
| **Total** | **180** | **180** | **180** | **540** | — |

## Reproduction

Every run with `seed=42` and `PYTHONHASHSEED=0` produces byte-identical skill
files. The `manifest_content_sha256` field in `manifest.json` can be used to
verify deterministic reproduction.

Expected metrics (skillfortify 0.4.4, medium threshold):

- Precision: 100% (270/270)
- Recall: 94.07% (254/270) — 16 intentional false negatives
- Wilson 95% CI for recall: [0.90592, 0.96320]

## Evaluation

Run the SkillFortify scanner against the benchmark:

```bash
skillfortify scan benchmark-output/skills/ --format json --severity-threshold medium
```

## Citation

See [CITATION.cff](CITATION.cff) or cite:

```bibtex
@article{bhardwaj2025skillfortify,
  title   = {SkillFortify: Static Analysis for AI Agent Skill Supply Chains},
  author  = {Bhardwaj, Varun Pratap},
  journal = {arXiv preprint arXiv:2603.00195},
  year    = {2025},
  doi     = {10.48550/arXiv.2603.00195}
}
```

Paper DOI: [10.5281/zenodo.18787663](https://doi.org/10.5281/zenodo.18787663)

## Citations and Prior Work

Static analysis of LLM agent security intersects with several concurrent efforts.
SkillFortifyBench is designed as a complement, not a replacement, to these
benchmarks:

- Holzbauer et al. 2026 — scanner-disagreement measurement across
  static tooling (arXiv:2603.16572).
- SkillClone (Zhu et al., ASE 2026) — clone-detection benchmark for
  agent skills (arXiv:2603.22447).
- MalTool (Hu et al. 2026) — tool-abuse pattern taxonomy
  (arXiv:2602.12194).
- InjecAgent (Zhan et al. 2024) — prompt-injection benchmark
  (arXiv:2403.02691).
- MCPTox (Wang et al., AAAI 2026) — MCP-specific attack corpus
  (arXiv:2508.14925).
- HarmBench (Mazeika et al. 2024) — broad LLM-harm benchmark
  (arXiv:2402.04249).

## Limitations (v1.0)

1. Synthetic-only generation. No real-world seed tier. Natural-distribution
   prevalence of A1..A13 is out of scope.
2. No hard-negative tier. Benign skills are diverse but not adversarially
   selected.
3. No cross-scanner leaderboard. Comparison vs. Semgrep / Bandit / Slither
   remains in private notebooks; public leaderboard deferred to v1.1.
4. No Gebru-style DATASHEET or MODEL-CARD. v1.1 will ship both.
5. Single-analyzer-version coverage (`skillfortify==0.4.4`). v1.1 will cover
   a version matrix (0.4.4, 0.5.0, ...) with per-version tagged results.
6. English-only skill bodies. No i18n in v1.0.

## v1.1 Roadmap (target: 2026 Q3)

- Real-world seed tier (small curated set of sanitized in-the-wild skills).
- Hard-negative tier (adversarial benign).
- Interactive leaderboard page.
- DATASHEET for Datasets (Gebru et al. format).
- MODEL-CARD analog for the generator.
- Multi-version analyzer matrix.

## License

MIT — see [LICENSE](LICENSE).

Note: The `benchmarks/` subtree is MIT-licensed per paper Section 12; the rest of
the SkillFortify repository is Elastic License 2.0.

## Links

- Paper: <https://arxiv.org/abs/2603.00195>
- SkillFortify: <https://github.com/varun369/skillfortify>
- [@varunPbhardwaj](https://twitter.com/varunPbhardwaj)
