# SkillFortifyBench Results

SkillFortify **0.6.0**, MEDIUM severity threshold, corpus generated
from seed=42 with `PYTHONHASHSEED=0`.

Every figure below is computed from `results/specimen-results.json`, which
holds one record per specimen: its label, the scanner's verdict, how many
findings it produced, and the highest severity among them. Totals and
breakdowns are two views of those same records, so they cannot disagree.

Reproduce with:

```bash
PYTHONHASHSEED=0 python -m benchmarks.metrics \
    --corpus benchmarks --output benchmarks/results
```

## Overall

| Metric | Value | Wilson 95% CI |
|--------|-------|---------------|
| Precision | 100.00% | [98.49%, 100.00%] |
| Recall | 92.59% | [88.84%, 95.15%] |
| Specificity | 100.00% | [98.60%, 100.00%] |
| F1 | 96.15% | — |

540 specimens: 250 TP, 0 FP, 270 TN, 20 FN.

F1 has no confidence interval here on purpose. It is not a binomial
proportion, so a Wilson interval computed on it would not describe
anything; the recall interval is what carries the uncertainty.

## Per format

| Format | Malicious | Detected | Missed | FP | Precision | Recall | Wilson 95% CI |
|--------|----------:|---------:|-------:|---:|----------:|-------:|---------------|
| claude | 90 | 87 | 3 | 0 | 100.00% | 96.67% | [90.65%, 98.86%] |
| mcp | 90 | 76 | 14 | 0 | 100.00% | 84.44% | [75.57%, 90.50%] |
| openclaw | 90 | 87 | 3 | 0 | 100.00% | 96.67% | [90.65%, 98.86%] |

## Per attack type

Behaviour names come from `attack_taxonomy.json`, which the generator
writes from the seed modules, so this table describes the specimens that
actually exist rather than a list maintained separately.

| Type | Behaviour | Total | Detected | Missed | Recall | Wilson 95% CI |
|------|-----------|------:|---------:|-------:|-------:|---------------|
| A1 | HTTP exfiltration | 30 | 28 | 2 | 93.33% | [78.68%, 98.15%] |
| A2 | DNS exfiltration | 18 | 17 | 1 | 94.44% | [74.24%, 99.01%] |
| A3 | Credential theft | 30 | 29 | 1 | 96.67% | [83.33%, 99.41%] |
| A4 | Arbitrary code execution | 30 | 30 | 0 | 100.00% | [88.65%, 100.00%] |
| A5 | File system tampering | 18 | 18 | 0 | 100.00% | [82.41%, 100.00%] |
| A6 | Privilege escalation | 18 | 18 | 0 | 100.00% | [82.41%, 100.00%] |
| A7 | Steganographic exfiltration | 24 | 24 | 0 | 100.00% | [86.20%, 100.00%] |
| A8 | Prompt injection | 24 | 21 | 3 | 87.50% | [69.00%, 95.66%] |
| A9 | Reverse shell | 24 | 24 | 0 | 100.00% | [86.20%, 100.00%] |
| A10 | Cryptocurrency mining | 12 | 12 | 0 | 100.00% | [75.75%, 100.00%] |
| A11 | Typosquatting | 8 | 4 | 4 | 50.00% | [21.52%, 78.48%] |
| A12 | Dependency confusion | 8 | 0 | 8 | 0.00% | [0.00%, 32.44%] |
| A13 | Encoded payload | 26 | 25 | 1 | 96.15% | [81.11%, 99.32%] |

## The 20 misses

By type: A1 (2), A2 (1), A3 (1), A8 (3), A11 (4), A12 (8), A13 (1).

These are gaps, not design decisions. An earlier version of this file
labelled a column *intentional false negatives*, which framed a limit of
the analyser as a property of the corpus and made the recall figure look
like a choice rather than a measurement.

- **A12 dependency confusion (all 8).** Deciding that an internal-looking
  package name also resolves on a public registry requires an index of
  what publicly exists. Static content analysis cannot answer it.
- **A11 typosquatting (half).** Same root cause: a name is a typosquat
  only relative to a set of real names.
- **The remainder** are specimens whose payload survives without any
  literal signal: an endpoint reachable only after decoding, or an
  instruction that carries no command at all.

Every missed specimen is listed individually in
`results/specimen-results.json` with `detected: false`.

## How the labels are assigned

Labels are assigned **by construction**: a specimen's class is the class
the generator drew it from, fixed before any scanner sees it. That makes
the labels exact and the corpus reproducible, and it also means a score
here measures coverage of a known catalogue of behaviours rather than
field accuracy on skills someone else wrote.

The detector and the corpus come from the same project. That is worth
stating plainly: it makes these numbers useful for tracking regressions
between releases, and weak as evidence against an adversary who knows
which patterns are checked.

## Corpus integrity

Malicious and benign specimens are emitted through one shared code path,
so both halves have the same install layout, frontmatter schema, inert
marker, and name vocabulary. `metrics/leakage.py` enumerates structural
features -- keys, path components, marker counts, closed-vocabulary values
-- and fails the build if any of them predicts the label. Scoring refuses
to run while a leak is present, because a metric taken over a leaking
corpus describes the corpus.

Of the 270 benign specimens, 90 (33%) contain dual-use constructs: 54
invoke `python -c` and 36 issue `curl` to package registries. Those 90
were the analyser's entire false-positive set before interpreter-flag
findings were graded by what the inline program does.

## Reproducibility

```bash
PYTHONHASHSEED=0 python -m benchmarks.generator \
    --output ./benchmark-output --seed 42
```

Manifest content SHA-256: `a725a79ebe1bc66aa68e960a71acaadc004261547cd0c756688866fc22d7c51e`

Two runs with the same seed produce byte-identical files and the same
manifest hash.

---

*Wilson intervals use z=1.96. Evaluated with SkillFortify 0.6.0.*
