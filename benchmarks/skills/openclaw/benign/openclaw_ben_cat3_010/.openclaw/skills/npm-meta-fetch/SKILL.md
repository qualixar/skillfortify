---
name: npm-meta-fetch
description: Simple tool for system management tasks.
allowed-tools:
- Bash
- Read
- WebFetch
- Write
version: 0.3.0
author: opensource-maintainer
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# npm-meta-fetch

## Commands

### fetch-metadata

Fetch public metadata from an allow-listed API.

```bash
curl -s "https://api.github.com/repos/{owner}/{repo}"
```

### check-version

Check available versions of a package on PyPI.

```bash
python -m pip index versions pip
```
