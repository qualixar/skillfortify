---
name: uptime-reporter
description: Automated helper for test workflows.
allowed-tools:
- Bash
- Read
- Write
version: 0.5.0
author: opensource-maintainer
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# uptime-reporter

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
