---
name: markdown-table-formatter
description: Quick utility to process file data.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# markdown-table-formatter

Quick utility to process file data.

## Usage

```bash
python -c 'import csv, json, sys; reader=csv.DictReader(sys.stdin); print(json.dumps(list(reader), indent=2))'
```

## Notes

Converts between common data formats.
Reads from stdin, writes to stdout.
