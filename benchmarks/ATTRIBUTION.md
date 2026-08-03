# Attribution

SkillFortifyBench attack patterns draw on the following published research and
public disclosures. All attack patterns in this benchmark are **inert text
reproductions**. No live exploit code is included. Every generated skill carries
the `SKILLFORTIFYBENCH:INERT` sentinel marker.

Behaviour names below match `attack_taxonomy.json`, which the generator writes
from the seed modules themselves. If a name here disagrees with that file, the
file is right.

## Attack Pattern Sources

| Attack Type | Behaviour | Source |
|-------------|-----------|--------|
| A1 | HTTP exfiltration | ClawHavoc (Koi Security / Yomtov, Feb 2026; analysis by Antiy CERT) |
| A2 | DNS exfiltration | ClawHavoc (Koi Security / Yomtov, Feb 2026) |
| A3 | Credential theft | ClawHavoc (Koi Security / Yomtov, Feb 2026); CVE-2026-21852 |
| A4 | Arbitrary code execution | ClawHavoc (Koi Security / Yomtov, Feb 2026); invariant-labs/mcp-injection-experiments; CVE-2026-25253 |
| A5 | File system tampering | ClawHavoc (Koi Security / Yomtov, Feb 2026) |
| A6 | Privilege escalation | ClawHavoc (Koi Security / Yomtov, Feb 2026) |
| A7 | Steganographic exfiltration | MalTool (Hu et al. 2026, arXiv:2602.12194); MCPTox (Wang et al. 2025, arXiv:2508.14925) |
| A8 | Prompt injection | InjecAgent (Zhan et al. 2024, arXiv:2403.02691); MalTool (arXiv:2602.12194); invariant-labs/mcp-injection-experiments |
| A9 | Reverse shell | ClawHavoc (Koi Security / Yomtov, Feb 2026); MalTool (arXiv:2602.12194) |
| A10 | Cryptocurrency mining | MalTool (arXiv:2602.12194) |
| A11 | Typosquatting | Agent Skills in the Wild (Liu et al. 2026, arXiv:2601.10338) |
| A12 | Dependency confusion | Agent Skills in the Wild (arXiv:2601.10338); MCPTox (arXiv:2508.14925) |
| A13 | Encoded payload | ClawHavoc (Koi Security / Yomtov, Feb 2026) |

## External Dataset Acknowledgments

| Dataset / Tool | Authors | Use in SkillFortifyBench |
|----------------|---------|--------------------------|
| ClawHavoc | Koi Security (Oren Yomtov); large-scale analysis by Antiy CERT | A1–A6, A9, A13 attack pattern templates |
| MalTool | Yuepeng Hu, Yuqi Jia, Mengyuan Li, Dawn Song, Neil Gong (arXiv:2602.12194) | A7–A10 behavioural patterns |
| InjecAgent | Qiusi Zhan, Zhixiang Liang, Zifan Ying, Daniel Kang (arXiv:2403.02691) | A8 injection pattern library |
| MCPTox | Zhiqiang Wang et al. (arXiv:2508.14925) | A7, A12 MCP-specific poisoning patterns |
| Agent Skills in the Wild | Yi Liu, Weizhe Wang, Ruitao Feng, Yao Zhang, Guangquan Xu, Gelei Deng, Yuekang Li, Leo Zhang (arXiv:2601.10338) | A11, A12 squatting pattern taxonomy |
| invariant-labs/mcp-injection-experiments | invariant-labs | A4, A8 tool-poisoning PoC structure |

Author lists above were checked against the arXiv API rather than copied from
a secondary source.

## Formats

All three slices use the packaging their runtime actually loads:

| Slice | Layout |
|-------|--------|
| `skills/claude/` | `.claude/skills/<name>/SKILL.md` |
| `skills/openclaw/` | `.openclaw/skills/<name>/SKILL.md`, with runtime requirements under `metadata.openclaw.requires` |
| `skills/mcp/` | `.mcp.json` with an `mcpServers` map |

Claude Code and OpenClaw both implement the
[Agent Skills](https://agentskills.io) open standard, so the two skill slices
share a file format and differ in load path and runtime metadata — which is
what makes them distinct discovery surfaces to test.

## Reproducibility

All 540 skills are generated deterministically from seed=42 using
`python -m benchmarks.generator --seed 42`. Byte-identical output is guaranteed
when `PYTHONHASHSEED=0` is set. See [CITATION.cff](CITATION.cff) for citation
information.

## CVE References

- **CVE-2026-21852** — Claude Code API-key exfiltration via `ANTHROPIC_BASE_URL`
  redirection (Check Point Research, CVSS 5.3)
- **CVE-2026-25253** — OpenClaw authentication-token theft leading to RCE via a
  crafted `gatewayUrl` query parameter (CWE-669, CVSS 8.8)

These informed the design of A3 and A4 respectively. No exploit code from
either is included; only the structural pattern, as inert text.
