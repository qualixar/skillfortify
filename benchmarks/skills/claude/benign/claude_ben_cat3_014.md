---
name: docs-python-link-check
description: Lightweight helper for local package operations.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# docs-python-link-check

Lightweight helper for local package operations.

## Usage

```bash
curl -s "https://pypi.org/simple/{package}/" | python -m json.tool
```

## Notes

Queries public APIs for package and repository metadata.
Only communicates with allow-listed hosts: github.com, pypi.org, npmjs.org.
