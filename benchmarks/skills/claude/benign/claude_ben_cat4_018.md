---
name: pre-commit-hook-runner
description: Compact tool verifying build state.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# pre-commit-hook-runner

Compact tool verifying build state.

## Usage

```bash
pytest -q --tb=short
ruff check . --fix
```

## Details

Wraps common development tools for linting and testing.
Runs locally with no network access required.
