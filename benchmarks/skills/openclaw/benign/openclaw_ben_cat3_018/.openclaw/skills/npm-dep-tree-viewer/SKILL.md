---
name: npm-dep-tree-viewer
description: Simple tool for data management tasks.
allowed-tools:
- Bash
- Read
- WebFetch
- Write
version: 1.3.0
author: opensource-maintainer
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# npm-dep-tree-viewer

## Commands

### fetch-metadata

Fetch public metadata from an allow-listed API.

```bash
curl -s "https://pypi.org/pypi/{package}/json"
```

### check-version

Check available versions of a package on PyPI.

```bash
python -m pip index versions pip
```
