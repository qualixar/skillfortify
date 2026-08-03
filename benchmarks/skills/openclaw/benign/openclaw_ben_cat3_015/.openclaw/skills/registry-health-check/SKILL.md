---
name: registry-health-check
description: Automated helper for environment workflows.
allowed-tools:
- Bash
- Read
- WebFetch
- Write
version: 2.0.0
author: community
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# registry-health-check

## Commands

### fetch-metadata

Fetch public metadata from an allow-listed API.

```bash
curl -s "https://api.github.com/users/{user}/repos"
```

### check-version

Check available versions of a package on PyPI.

```bash
python -m pip index versions pip
```
