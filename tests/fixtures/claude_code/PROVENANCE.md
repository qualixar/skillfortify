# Fixture provenance

Skills copied verbatim from Anthropic's public Agent Skills repository.
They are **not** authored here. A format adapter must be validated against
artifacts the upstream ecosystem produced, not against fixtures written
from our own reading of a specification -- that shared assumption is what
let the original `.claude/skills/*.md` parser pass its tests while finding
zero skills on a real machine.

| Field | Value |
|-------|-------|
| Source repository | https://github.com/anthropics/skills |
| Source path | `skills/<name>/SKILL.md` |
| Commit | `b29e7cf65e5cb78a5ac33d582270551bc74a14eb` (main) |
| Fetched | 2026-08-03 |
| Specification | `spec/agent-skills-spec.md` in the same repository |
| Licence | See upstream repository and each skill's own licence field |

Files are laid out as `.claude/skills/<name>/SKILL.md` so the fixture root
can be handed to the parser exactly as a project directory would be.

| Skill | SHA-256 |
|-------|---------|
| `brand-guidelines/SKILL.md` | `1120b3769e2985cefb3d25be981b1f914abeba57ae079b83c20c666c164fa9fe` |
| `docx/SKILL.md` | `8017469ea95fb7d28225c62daf8e2f3492a7b516fc64c18c28977cbf8980b7fe` |
| `mcp-builder/SKILL.md` | `0f4592dcb53cf2b5d6b7febee6b4152018b565551a1c29e3c612f57b218ab295` |
| `pdf/SKILL.md` | `9f78b8359fbd4943ad260a7a1e436e5a96503406d6c34e99f69223d647d85b9c` |

## Refreshing

Re-fetch with `gh api "repos/anthropics/skills/contents/skills/<name>/SKILL.md?ref=<sha>"`,
then update the commit, date, and hashes. Never hand-edit these files.
