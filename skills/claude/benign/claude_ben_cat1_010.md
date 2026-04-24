---
name: log-file-rotator
description: Quick utility to process report data.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# log-file-rotator

Quick utility to process report data.

## Usage

```bash
python -m json.tool input.json output.json
```

## Details

Uses pathlib and shutil for safe file operations.
Reads input files, processes content, writes output.
