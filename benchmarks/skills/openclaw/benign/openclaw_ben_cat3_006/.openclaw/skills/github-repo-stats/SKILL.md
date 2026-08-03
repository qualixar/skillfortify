---
name: github-repo-stats
description: Fast utility scanning build resources.
allowed-tools:
- Bash
- Read
- WebFetch
- Write
version: 0.4.0
author: community
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# github-repo-stats

## Commands

### fetch-metadata

Fetch public metadata from an allow-listed API.

```bash
curl -s "https://pypi.org/simple/{package}/"
```

### check-version

Check available versions of a package on PyPI.

```bash
python -m pip index versions pip
```
