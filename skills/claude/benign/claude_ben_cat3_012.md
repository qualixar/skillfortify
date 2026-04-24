---
name: pypi-download-counter
description: Routine utility auditing report info.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# pypi-download-counter

Routine utility auditing report info.

## Usage

```bash
curl -s "https://api.github.com/repos/{owner}/{repo}/issues" | python -m json.tool
```

## Notes

Queries public APIs for package and repository metadata.
Only communicates with allow-listed hosts: github.com, pypi.org, npmjs.org.
