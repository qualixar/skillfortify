---
name: file-size-reporter
description: Simple tool for config management tasks.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# file-size-reporter

Simple tool for config management tasks.

## Usage

```bash
python -m json.tool input.json output.json
```

## Details

Uses pathlib and shutil for safe file operations.
Reads input files, processes content, writes output.
