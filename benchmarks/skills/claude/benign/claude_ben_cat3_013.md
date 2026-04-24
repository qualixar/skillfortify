---
name: npm-audit-reporter
description: Automated helper for project workflows.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# npm-audit-reporter

Automated helper for project workflows.

## Usage

```bash
curl -s "https://registry.npmjs.org/{package}" | python -m json.tool
```

## Notes

Queries public APIs for package and repository metadata.
Only communicates with allow-listed hosts: github.com, pypi.org, npmjs.org.
