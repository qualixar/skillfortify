# Fixture provenance

These skills were copied verbatim from the official OpenClaw skill registry.
They are **not** authored in this repository. That is the point: a format
adapter must be validated against artifacts produced by the upstream
ecosystem, not against fixtures written from our own reading of a spec.

| Field | Value |
|-------|-------|
| Source repository | https://github.com/openclaw/clawhub |
| Source path | `.agents/skills/<name>/SKILL.md` |
| Commit | `4ae518011a5b0453aee7279b23ff11cd9d8dd292` (main) |
| Fetched | 2026-08-03 |
| Licence | See upstream repository |

## Files

| Skill | SHA-256 |
|-------|---------|
| `openclaw-brand/SKILL.md` | `c4dd49801148d03ad4da7652ae5cbb9dcc01b4b56dbd343c8357941f340d2050` |
| `controlling-costs/SKILL.md` | `a0823b1b1581c7932855ff68fca3eab72d49bac4a920eae9c6633e837c6204ed` |
| `clawhub-moderation/SKILL.md` | `e32197e6afa226e8c7252e02f46aa4cd0f7f97b3c7375e6acbec1cc42635ea1a` |

## Refreshing

Re-fetch with `gh api "repos/openclaw/clawhub/contents/.agents/skills/<name>/SKILL.md?ref=<sha>"`,
then update the commit, date, and hashes above. Do not hand-edit the SKILL.md
files -- editing them turns an upstream artifact back into one of ours.
