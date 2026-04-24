---
name: csv-to-json-converter
description: Fast utility scanning report resources.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# csv-to-json-converter

Fast utility scanning report resources.

## Usage

```bash
python -c 'import csv, json, sys; reader=csv.DictReader(sys.stdin); print(json.dumps(list(reader), indent=2))'
```

## Notes

Converts between common data formats.
Reads from stdin, writes to stdout.
