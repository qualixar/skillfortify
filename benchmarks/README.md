# SkillFortifyBench

A 540-skill benchmark for evaluating scanners of AI agent skill supply chains,
across the three surfaces an agent actually loads from.

## What this is, and what it is not

SkillFortifyBench is a **deterministic synthetic corpus**. Every specimen is
generated from a seed, and its label is the class the generator drew from —
not a judgement made after the fact. That makes the corpus reproducible and
its labels exact, and it also bounds what a score against it can mean:

- It measures whether a scanner recognises a catalogue of known attack
  behaviours expressed in real skill packaging.
- It does **not** estimate field accuracy on marketplace skills. The specimens
  are constructed, not collected, and their distribution is chosen rather than
  observed.

Numbers here are reported for `skillfortify` at the version in
`results/summary.json`. They are recomputed on each release rather than quoted
from the paper.

## Layout

Each specimen is a self-contained installation root, laid out the way its
runtime loads skills, so that scanning a specimen exercises the same discovery
path that scanning a real machine does:

```
skills/claude/malicious/<specimen-id>/.claude/skills/<name>/SKILL.md
skills/openclaw/benign/<specimen-id>/.openclaw/skills/<name>/SKILL.md
skills/mcp/malicious/<specimen-id>/.mcp.json
```

Claude Code and OpenClaw both implement the
[Agent Skills](https://agentskills.io) open standard: a skill is a *directory*
containing `SKILL.md` with YAML frontmatter. The two differ in where the
runtime looks and in the runtime-specific metadata a skill may carry, which is
what the two slices exercise.

Both classes are emitted through one shared code path, so the malicious and
benign halves are structurally identical — same install path, same frontmatter
schema, same inert marker, same name vocabulary. `metrics/leakage.py` checks
this mechanically, and the release gate fails if any structural feature
predicts the label.

## Contents

- `skills/claude/` — 180 Claude Code skills (90 malicious + 90 benign)
- `skills/mcp/` — 180 MCP server configs (90 malicious + 90 benign)
- `skills/openclaw/` — 180 OpenClaw skills (90 malicious + 90 benign)
- `manifest.json` — 540-entry manifest with per-file SHA-256
- `attack_taxonomy.json` — attack types and formal classes, written by the
  generator from the seed modules themselves
- `results/` — per-specimen scan records and the summary they aggregate to

## Quick start

```bash
PYTHONHASHSEED=0 python -m benchmarks.generator --output ./benchmark-output --seed 42
```

Scoring a scanner means scanning each specimen root on its own and comparing
the verdict to the manifest label:

```bash
PYTHONHASHSEED=0 python -m benchmarks.metrics --corpus benchmarks --output benchmarks/results
```

One specimen yields one prediction, so the totals and the per-type breakdown
are two views of the same records and cannot disagree.

## Attack types and measured recall

Behaviour names are read from `attack_taxonomy.json`, which the generator
writes from the seed classes, so this table cannot drift from the specimens it
describes.

| Type | Claude | MCP | OpenClaw | Total | Behaviour | Detected | Recall | Wilson 95% CI |
|------|-------:|----:|---------:|------:|-----------|---------:|-------:|---------------|
| A1 | 10 | 10 | 10 | 30 | HTTP exfiltration | 28 | 93.3% | [78.7%, 98.2%] |
| A2 | 6 | 6 | 6 | 18 | DNS exfiltration | 17 | 94.4% | [74.2%, 99.0%] |
| A3 | 10 | 10 | 10 | 30 | Credential theft | 29 | 96.7% | [83.3%, 99.4%] |
| A4 | 10 | 10 | 10 | 30 | Arbitrary code execution | 30 | 100.0% | [88.6%, 100.0%] |
| A5 | 6 | 6 | 6 | 18 | File system tampering | 18 | 100.0% | [82.4%, 100.0%] |
| A6 | 6 | 6 | 6 | 18 | Privilege escalation | 18 | 100.0% | [82.4%, 100.0%] |
| A7 | 8 | 8 | 8 | 24 | Steganographic exfiltration | 24 | 100.0% | [86.2%, 100.0%] |
| A8 | 8 | 8 | 8 | 24 | Prompt injection | 21 | 87.5% | [69.0%, 95.7%] |
| A9 | 8 | 8 | 8 | 24 | Reverse shell | 24 | 100.0% | [86.2%, 100.0%] |
| A10 | 4 | 4 | 4 | 12 | Cryptocurrency mining | 12 | 100.0% | [75.7%, 100.0%] |
| A11 | 4 | 2 | 2 | 8 | Typosquatting | 4 | 50.0% | [21.5%, 78.5%] |
| A12 | 2 | 4 | 2 | 8 | Dependency confusion | 0 | 0.0% | [0.0%, 32.4%] |
| A13 | 8 | 8 | 10 | 26 | Encoded payload | 25 | 96.2% | [81.1%, 99.3%] |
| **Malicious** | **90** | **90** | **90** | **270** | — | **250** | **92.59%** | [88.84%, 95.15%] |
| Benign | 90 | 90 | 90 | 270 | 5 categories | — | — | — |

**A12 dependency confusion is not detected at all, and half of A11
typosquatting is missed.** Both need registry knowledge the analyser does not
have: deciding that an internal-looking package name also resolves publicly,
or that a name is a near-miss of a popular one, requires an index of what
legitimately exists. These are open gaps, published rather than omitted.

## Measured results

`skillfortify` at the version recorded in `results/summary.json`, MEDIUM
severity threshold:

| Format | Precision | Recall | F1 | TP | FP | TN | FN |
|--------|----------:|-------:|---:|---:|---:|---:|---:|
| Claude | 100.0% | 96.7% | 98.3% | 87 | 0 | 90 | 3 |
| MCP | 100.0% | 84.4% | 91.6% | 76 | 0 | 90 | 14 |
| OpenClaw | 100.0% | 96.7% | 98.3% | 87 | 0 | 90 | 3 |
| **Overall** | **100.0%** | **92.59%** | **96.15%** | **250** | **0** | **270** | **20** |

Wilson 95% intervals: recall [88.84%, 95.15%], precision [98.49%, 100%],
specificity [98.60%, 100%].

**How to read the precision figure.** It says no benign specimen in this
corpus produced a finding at or above MEDIUM. It is not an estimate of the
false-positive rate on real skills, because the benign half is generated
rather than collected. It is worth more than a trivially clean run, though:
90 of the 270 benign specimens (33%) contain dual-use constructs — 54 invoke
`python -c`, 36 issue `curl` to package registries — and those 90 were the
analyser's entire false-positive set before interpreter-flag findings were
graded by what the inline program actually does.

Every number above is recomputed from `results/specimen-results.json`, which
records the label, verdict, finding count, and highest severity for all 540
specimens.

## Reproduction

Every run with `seed=42` and `PYTHONHASHSEED=0` produces byte-identical files.
`manifest.json` carries a `manifest_content_sha256` over the entry list and a
SHA-256 per file, so a regenerated tree can be compared entry by entry.

## Limitations

1. **Synthetic only.** No in-the-wild seed tier. The prevalence of A1–A13 here
   is a design choice, not an observed distribution.
2. **Constructed bodies.** Payloads are compact and idiomatic rather than
   obfuscated the way a real campaign would be. A scanner that does well here
   has not been shown to survive an adversary who knows it is being scanned.
3. **Hard negatives are present but narrow.** A third of the benign half uses
   dual-use constructs; none is an adversarially built look-alike.
4. **Detector and corpus share an author.** Both come from this project, so a
   good score is evidence about coverage of a known catalogue, not an
   independent evaluation. Cross-scanner comparison is not published.
5. **Single analyser version** per results file.
6. **English-only skill bodies.**

## License

MIT — see [LICENSE](LICENSE).

The `benchmarks/` subtree is MIT-licensed; the rest of the SkillFortify
repository is Elastic License 2.0.

## Citation

See [CITATION.cff](CITATION.cff).

## Related benchmarks

SkillFortifyBench is a complement to, not a replacement for:

- Holzbauer et al. 2026 — scanner-disagreement measurement (arXiv:2603.16572)
- SkillClone (Zhu et al., ASE 2026) — clone detection (arXiv:2603.22447)
- MalTool (Hu et al. 2026) — tool-abuse taxonomy (arXiv:2602.12194)
- InjecAgent (Zhan et al. 2024) — prompt injection (arXiv:2403.02691)
- MCPTox (Wang et al., AAAI 2026) — MCP attack corpus (arXiv:2508.14925)
- HarmBench (Mazeika et al. 2024) — broad LLM harm (arXiv:2402.04249)

## Links

- SkillFortify: <https://github.com/qualixar/skillfortify>
- [@varunPbhardwaj](https://twitter.com/varunPbhardwaj)
