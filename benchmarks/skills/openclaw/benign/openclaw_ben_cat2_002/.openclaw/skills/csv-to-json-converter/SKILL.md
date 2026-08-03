---
name: csv-to-json-converter
description: Compact tool verifying project state.
allowed-tools:
- Bash
- Read
- Write
version: 1.1.0
author: opensource-maintainer
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# csv-to-json-converter

## Commands

### convert

Convert and pretty-print JSON data.

```bash
python -m json.tool
```

### validate

Validate YAML input from stdin.

```bash
python -c 'import yaml, sys; yaml.safe_load(sys.stdin)'
```
