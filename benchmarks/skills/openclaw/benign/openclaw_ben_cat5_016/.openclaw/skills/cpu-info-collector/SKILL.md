---
name: cpu-info-collector
description: Simple tool for system management tasks.
allowed-tools:
- Bash
- Read
- Write
version: 1.0.0
author: community
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# cpu-info-collector

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
