---
name: docs-python-link-check
description: Automated helper for package workflows.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# docs-python-link-check

Automated helper for package workflows.

## Usage

```bash
curl -s "https://api.github.com/users/{user}/repos" | python -m json.tool
```

## Notes

Queries public APIs for package and repository metadata.
Only communicates with allow-listed hosts: github.com, pypi.org, npmjs.org.
