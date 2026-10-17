# Sources and missing connectors

Use these source names when the fact comes from that place. The version is the catalogue or package version, or `none` when there is no release id. The date is `retrieved_at` from the tool envelope, written YYYY-MM-DD in Australia/Sydney. For a bundled file, use the `retrieved` date in that file.

| Fact | Source name | Version |
|---|---|---|
| ASD page text from `mcp__asd__asd_get_item` | ASD ACSC | `none`, unless the envelope gives a version |
| A bundled Defender or Sentinel column | The schema file's `source_name` | The schema file's `version` |
| Whether a Sigma modifier is in the Kusto list | pySigma Kusto backend | The `version` in `kusto-support.yaml` |
| Keeping author and id on a SigmaHQ rule | SigmaHQ Detection Rule License | 1.1 |

SigmaHQ rules are shared under the Detection Rule License 1.1. When a rule is shown, keep the author and the id from the rule record.
Source: SigmaHQ Detection Rule License, 1.1, retrieved 2026-10-16.

That licence note was recorded from this distribution's connector research on 2026-10-16. Copy the author and the id from `mcp__sigma__sigma_get` or `mcp__sigma__sigma_search`. Do not invent either field.

## When a connector is missing

If a tool is not available, or it returns no record, name the missing source and continue with the other steps. Do not guess a technique name, a tactic, a SigmaHQ id, or a SigmaHQ author.

| Tool | Source to name when it is missing |
|---|---|
| `mcp__attack__attack_technique` | MITRE ATT&CK |
| `mcp__sigma__sigma_search` | SigmaHQ rules |
| `mcp__sigma__sigma_get` | SigmaHQ rules |
| `mcp__sigma__sigma_convert` | pySigma Kusto backend |
| `mcp__asd__asd_get_item` | ASD ACSC |

`sigma_convert` is the only step that produces pySigma KQL. A hand draft is not that output. Say so when you show one.
