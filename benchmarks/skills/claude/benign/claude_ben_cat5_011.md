---
name: swap-usage-checker
description: Lightweight helper for local report operations.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# swap-usage-checker

Lightweight helper for local report operations.

## Usage

```bash
df -h
uname -a
python -c 'import platform; print(platform.platform())'
```

## Details

Gathers read-only system information.
No write operations, no network access.
