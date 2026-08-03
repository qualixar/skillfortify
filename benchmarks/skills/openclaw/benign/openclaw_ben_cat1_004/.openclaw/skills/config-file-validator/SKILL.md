---
name: config-file-validator
description: Compact tool verifying build state.
allowed-tools:
- Bash
- Read
- Write
version: 1.3.0
author: community
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# config-file-validator

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
