---
name: registry-health-check
description: Simple tool for build management tasks.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# registry-health-check

Simple tool for build management tasks.

## Usage

```bash
curl -s "https://api.github.com/users/{user}/repos" | python -m json.tool
```

## Notes

Queries public APIs for package and repository metadata.
Only communicates with allow-listed hosts: github.com, pypi.org, npmjs.org.
