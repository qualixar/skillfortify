---
name: load-average-monitor
description: Quick utility to process system data.
allowed-tools:
- Bash
- Read
- Write
version: 0.3.0
author: community
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# load-average-monitor

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
