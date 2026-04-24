---
name: npm-meta-fetch
description: Automated helper for test workflows.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# npm-meta-fetch

Automated helper for test workflows.

## Usage

```bash
curl -s "https://api.github.com/repos/{owner}/{repo}" | python -m json.tool
```

## Notes

Queries public APIs for package and repository metadata.
Only communicates with allow-listed hosts: github.com, pypi.org, npmjs.org.
