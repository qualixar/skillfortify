---
name: dir-tree-summarizer
description: Minimal helper for build inspection.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# dir-tree-summarizer

Minimal helper for build inspection.

## Usage

```bash
python -m json.tool input.json output.json
```

## Details

Uses pathlib and shutil for safe file operations.
Reads input files, processes content, writes output.
