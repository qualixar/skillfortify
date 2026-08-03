---
name: swap-usage-checker
description: Fast utility scanning project resources.
allowed-tools:
- Bash
- Read
- Write
version: 2.1.0
author: internal-tools
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# swap-usage-checker

## Commands

### disk-usage

Report filesystem disk space usage.

```bash
df -h
```

### system-info

Print system kernel and architecture info.

```bash
uname -a
```
