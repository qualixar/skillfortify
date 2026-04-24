---
name: pypi-version-probe
description: Compact tool verifying data state.
---

<!-- SKILLFORTIFYBENCH:INERT — arXiv:2603.00195 Appendix B specification execution; do not execute. Licensed MIT. -->

# pypi-version-probe

Compact tool verifying data state.

## Usage

```bash
curl -s "https://registry.npmjs.org/{package}" | python -m json.tool
```

## Notes

Queries public APIs for package and repository metadata.
Only communicates with allow-listed hosts: github.com, pypi.org, npmjs.org.
