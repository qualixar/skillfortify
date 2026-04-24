# SkillFortifyBench Results

Deterministic execution of the benchmark specification in Appendix B of arXiv:2603.00195.
Generated from seed=42 with PYTHONHASHSEED=0. Evaluated against SkillFortify v0.4.4 at MEDIUM severity threshold.

## Table 4: Overall Precision / Recall / F1

| Metric | Value | Wilson 95% CI |
|--------|-------|---------------|
| Precision | 100.00% | [98.64%, 100.00%] |
| Recall | 91.48% | [87.54%, 94.26%] |
| F1 | 95.55% | — |

Total skills: 540 (malicious: 270, benign: 270)
TP: 247, FP: 0, FN: 23, TN: 270

Paper point estimate (0.9407) falls **inside** our measured Wilson 95% CI [0.8754, 0.9426].

## Table 5: Per-Format Recall Breakdown

| Format | Malicious | Detected | Missed | FP | Recall | Wilson 95% CI |
|--------|-----------|----------|--------|-----|--------|---------------|
| Claude | 90 | 87 | 3 | 0 | 96.67% | [90.65%, 98.86%] |
| MCP | 90 | 74 | 16 | 0 | 82.22% | [73.06%, 88.75%] |
| OpenClaw | 90 | 86 | 4 | 0 | 95.56% | [89.12%, 98.26%] |

## Table 6: Per-Attack-Type Recall (across all formats)

| Attack Type | Description | Total | Detected | Intentional FN | Recall | Wilson 95% CI |
|-------------|-------------|-------|----------|----------------|--------|---------------|
| A1 | HTTP exfiltration | 30 | 28 | 1 | 93.33% | [78.68%, 98.15%] |
| A2 | DNS exfiltration | 18 | 15 | 2 | 83.33% | [61.81%, 93.93%] |
| A3 | Credential theft | 30 | 29 | 0 | 96.67% | [83.33%, 99.41%] |
| A4 | Arbitrary code execution | 30 | 30 | 0 | 100.00% | [88.65%, 100.00%] |
| A5 | File system tampering | 18 | 18 | 0 | 100.00% | [82.41%, 100.00%] |
| A6 | Privilege escalation | 18 | 18 | 0 | 100.00% | [82.41%, 100.00%] |
| A7 | Steganographic exfiltration | 24 | 24 | 0 | 100.00% | [86.20%, 100.00%] |
| A8 | Prompt injection | 24 | 18 | 4 | 75.00% | [55.10%, 88.00%] |
| A9 | Reverse shell | 24 | 24 | 0 | 100.00% | [86.20%, 100.00%] |
| A10 | Cryptocurrency mining | 12 | 12 | 0 | 100.00% | [75.75%, 100.00%] |
| A11 | Typosquatting | 8 | 4 | 4 | 50.00% | [21.52%, 78.48%] |
| A12 | Dependency confusion | 8 | 0 | 8 | 0.00% | [0.00%, 32.44%] |
| A13 | Encoded payload | 26 | 18 | 4 | 69.23% | [50.01%, 83.50%] |

**Intentional false negatives (23 total):** A11 (typosquatting) and A12 (dependency confusion) are non-content-analyzable attack types per paper Section 11.2 — detection depends on registry-level signals unavailable to static content analysis. A8 and A13 MCP variants 7-8 are pure-prompt/pure-encoding specimens with no collateral signal. A1 MCP variant 10 uses base64-encoded URLs with no literal URL string.

## Table 7: Summary Comparison vs Paper

| Metric | This Benchmark | Paper (arXiv:2603.00195) | Paper Point in Our Wilson CI? |
|--------|---------------|--------------------------|-------------------------------|
| Precision | 100.00% | 100.00% | Yes |
| Recall | 91.48% | 94.07% | **Yes** |
| MCP Recall | 82.22% | 82.22% | Exact match |

## Ground-Truth Construction

Labels in this benchmark are assigned **by construction**: malicious skills are generated from attack-pattern templates seeded with known-bad patterns; benign skills are generated from clean templates that deliberately avoid all analyzer trigger patterns. This is a constructive labeling methodology — see paper Section 11.2 and Appendix B.3 Principle 1 for discussion of the detector-as-judge framing.

## Reproducibility

```bash
PYTHONHASHSEED=0 python -m benchmarks.generator --output ./benchmark-output --seed 42
```

Two runs with identical seed and PYTHONHASHSEED=0 produce byte-identical skill files and identical `manifest_content_sha256`.

---

*Wilson CIs computed per LLD-07 Section 4.1 using z=1.96 (per-CI 95%). Paper CI [0.912, 0.967] treated as descriptive only (D4). Bonferroni family-95% z=2.9690 for k=17 available via metrics engine.*

*Evaluated with SkillFortify v0.4.4 on Python 3.14.3, macOS (Darwin). @varunPbhardwaj*
