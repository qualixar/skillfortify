---
name: isort-import-sorter
description: Compact tool verifying file state.
allowed-tools:
- Bash
- Read
- Write
version: 0.2.0
author: internal-tools
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# isort-import-sorter

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
