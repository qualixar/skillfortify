---
name: yaml-merger
description: Compact tool verifying config state.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# yaml-merger

Compact tool verifying config state.

## Usage

```bash
python -m json.tool input.json output.json
```

## Details

Uses pathlib and shutil for safe file operations.
Reads input files, processes content, writes output.
