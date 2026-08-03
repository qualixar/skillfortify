---
name: dir-tree-summarizer
description: Simple tool for data management tasks.
allowed-tools:
- Bash
- Read
- Write
version: 2.1.0
author: community
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# dir-tree-summarizer

## Commands

### list-files

List JSON files in the current directory tree.

```bash
find . -name '*.json' -type f
```

### validate-json

Validate and pretty-print a JSON file.

```bash
python -m json.tool --no-ensure-ascii
```
