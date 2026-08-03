---
name: coverage-line-annotator
description: Minimal helper for report inspection.
allowed-tools:
- Bash
- Read
- Write
version: 1.3.0
author: community
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# coverage-line-annotator

## Commands

### lint

Run ruff linter on the current directory.

```bash
ruff check . --output-format=json
```

### test

Run pytest with short traceback output.

```bash
pytest -q --tb=short
```
