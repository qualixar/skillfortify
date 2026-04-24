---
name: kernel-version-check
description: Compact tool verifying data state.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# kernel-version-check

Compact tool verifying data state.

## Usage

```bash
df -h
uname -a
python -c 'import platform; print(platform.platform())'
```

## Details

Gathers read-only system information.
No write operations, no network access.
