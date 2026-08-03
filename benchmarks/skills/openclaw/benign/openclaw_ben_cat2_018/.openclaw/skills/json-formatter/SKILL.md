---
name: json-formatter
description: Routine utility auditing package info.
allowed-tools:
- Bash
- Read
- Write
version: 1.2.0
author: verified-publisher
metadata:
  openclaw:
    requires:
      bins: []
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# json-formatter

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
