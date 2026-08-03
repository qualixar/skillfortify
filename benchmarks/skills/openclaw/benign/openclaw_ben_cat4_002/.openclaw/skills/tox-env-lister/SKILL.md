---
name: tox-env-lister
description: Lightweight helper for local data operations.
allowed-tools:
- Bash
- Read
- Write
version: 2.3.1
author: community
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# tox-env-lister

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
