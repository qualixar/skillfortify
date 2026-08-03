---
name: csv-row-counter
description: Fast utility scanning system resources.
allowed-tools:
- Bash
- Read
- Write
version: 1.1.0
author: verified-publisher
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# csv-row-counter

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
