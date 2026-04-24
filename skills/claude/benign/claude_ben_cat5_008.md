---
name: os-release-reader
description: Minimal helper for environment inspection.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# os-release-reader

Minimal helper for environment inspection.

## Usage

```bash
df -h
uname -a
python -c 'import platform; print(platform.platform())'
```

## Details

Gathers read-only system information.
No write operations, no network access.
