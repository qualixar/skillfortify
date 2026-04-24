---
name: xml-pretty-printer
description: Simple tool for system management tasks.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# xml-pretty-printer

Simple tool for system management tasks.

## Usage

```bash
python -c 'import csv, json, sys; reader=csv.DictReader(sys.stdin); print(json.dumps(list(reader), indent=2))'
```

## Notes

Converts between common data formats.
Reads from stdin, writes to stdout.
