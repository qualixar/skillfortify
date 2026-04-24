# Attribution

SkillFortifyBench attack patterns draw on the following published research and
public disclosures. All attack patterns in this benchmark are **inert text
reproductions**. No live exploit code is included. Every generated skill carries
the `SKILLFORTIFYBENCH:INERT` sentinel marker.

## Attack Pattern Sources

| Attack Type | Description | Source |
|-------------|-------------|--------|
| A1 | HTTP exfiltration | ClawHavoc (Bhardwaj 2025, arXiv:2602.20867) |
| A2 | DNS exfiltration | ClawHavoc (arXiv:2602.20867) |
| A3 | Prompt injection | ClawHavoc (arXiv:2602.20867); InjecAgent (Zhan et al. 2024, arXiv:2403.02691); CVE-2026-21852 |
| A4 | Tool poisoning | ClawHavoc (arXiv:2602.20867); invariant-labs/mcp-injection-experiments; CVE-2026-25253 |
| A5 | Credential theft | ClawHavoc (arXiv:2602.20867) |
| A6 | Privilege escalation | ClawHavoc (arXiv:2602.20867) |
| A7 | Arbitrary code execution | MalTool (Hu et al. 2026, arXiv:2602.12194); MCPTox (Wang et al. 2026, arXiv:2508.14925) |
| A8 | Indirect prompt injection | MalTool (arXiv:2602.12194); InjecAgent (arXiv:2403.02691); invariant-labs/mcp-injection-experiments |
| A9 | Shadow tool registration | ClawHavoc (arXiv:2602.20867); MalTool (arXiv:2602.12194) |
| A10 | Dependency confusion | MalTool (arXiv:2602.12194); MCPTox (arXiv:2508.14925) |
| A11 | Skill squatting | Agent Skills in the Wild (Liu et al. 2026, arXiv:2601.10338) |
| A12 | Typosquatting | Agent Skills in the Wild (arXiv:2601.10338) |
| A13 | Multi-vector composite | ClawHavoc (arXiv:2602.20867) |

## External Dataset Acknowledgments

| Dataset / Tool | Authors | Use in SkillFortifyBench |
|----------------|---------|--------------------------|
| ClawHavoc | Bhardwaj 2025 | A1-A6, A9, A13 attack pattern templates |
| MalTool | Hu et al. 2026 | A7, A8, A9, A10 behavioural patterns |
| InjecAgent | Zhan et al. 2024 | A3, A8 injection pattern library |
| MCPTox | Wang et al. 2026 | A7, A10 MCP-specific poisoning patterns |
| Agent Skills in the Wild | Liu et al. 2026 | A11, A12 squatting pattern taxonomy |
| invariant-labs/mcp-injection-experiments | invariant-labs | A4, A8 tool-poisoning PoC structure |

## OpenClaw Name Disambiguation

"OpenClaw" in this benchmark refers to the open skill format defined in
Section 3.2 of the SkillFortify paper (arXiv:2603.00195), specified as YAML
manifests with `name`, `version`, `commands`, and `permissions` fields. It is
not affiliated with any external project sharing a similar name.

## Reproducibility

All 540 skills are generated deterministically from seed=42 using
`python -m benchmarks.generator --seed 42`. Byte-identical output is guaranteed
when `PYTHONHASHSEED=0` is set. See [CITATION.cff](CITATION.cff) for citation
information.

## CVE References

- **CVE-2026-21852** — MCP prompt injection via tool description fields
- **CVE-2026-25253** — MCP tool poisoning via manipulated server manifests

These CVEs informed the design of A3 and A4 attack patterns respectively. No
exploit code from these CVEs is included; only the structural pattern is
represented as inert text.
