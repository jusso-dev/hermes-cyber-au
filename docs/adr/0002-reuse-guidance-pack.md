# ADR 0002: Depend on the guidance pack at a pinned commit

## Status

Proposed. Needs the maintainer's decision (issue #19).

## Context

The Australian cyber guidance pack lives at `jusso-dev/hermes-skills/plugins/hermes-cyber-au` (MIT). It installs with `hermes plugins install jusso-dev/hermes-skills/plugins/hermes-cyber-au`. The newest commit at the time of writing is `2b026c8c8c86dd1d1fa6696ca4104fa655e5c1c5` (11 October 2026).

What each side ships, checked on 18 October 2026:

| | Guidance pack (`hermes-cyber-au`, MIT) | This distribution (`cyber-au`, Apache-2.0) |
|---|---|---|
| Skills | aws-cloudwatch-expert, detection-engineering, essential-eight-assessor, incident-response-au, ism-control-lookup, sentinel-expert, threat-intel-check | acsc-advisory-digest, au-org-exposure, daily-briefing, essentials-assessment, executive-briefing, google-ti-dtm, harness-sample, incident-triage, ioc-enrichment, ism-control-lookup, misp, ndb-breach-notification, opencti, phishing-analysis, radar-au, soci-reporting, taxii-ctis, threat-hunting, virustotal, vuln-prioritisation |
| Tools | `cyber_au_search`, `cyber_au_control`, `cyber_au_check_query`, `cyber_au_live_query`, `cyber_au_osint_lookup`, `cyber_au_log_qa`, `cyber_au_propose_response`, `cyber_au_source_trust` | `intel_search`, `intel_get`, `intel_add_observation`, `intel_export_stix`, plus MCP connector tools under `mcp__<server>__*` |
| Knowledge | Allowlisted knowledge snapshot and an eval set | Live connectors (ISM OSCAL, Essentials, ASD feeds) and the local intel store |

Findings:

- **Skill name clash:** `ism-control-lookup` exists in both. Installed together, one shadows the other. This distribution's version reads the ISM OSCAL connector, so it tracks the current ISM release. The pack's version reads the pack's knowledge snapshot.
- **Overlap without a name clash:** `essential-eight-assessor` (pack) and `essentials-assessment` (here) cover the same ground. Since 15 October 2026, the one here also covers the ASD Essentials priority phases.
- **Tool names do not collide:** the pack uses `cyber_au_*`, this distribution `intel_*` and `mcp__*`.
- **Licences are compatible:** MIT code can be used in an Apache-2.0 project if the MIT notice is kept. Apache-2.0 code cannot be relicensed as MIT, so nothing should move the other way without the author's consent. The author is the same person here.
- **Skills unique to the pack:** Sentinel, CloudWatch and detection engineering. They have no equivalent here.

## Options

1. **Depend.** Bootstrap installs the pack at a pinned commit. This distribution adds connectors, the store, routines and its own skills. The pack drops or renames its `ism-control-lookup` (or this side renames), and `essential-eight-assessor` is marked superseded by `essentials-assessment`.
2. **Vendor.** Copy the pack's unique skills in at a pinned commit, with a sync script and the MIT notice in `NOTICE`. Two copies of each skill exist, and fixes have to be synced.
3. **Replace.** Move the pack's unique skills here and mark the pack superseded. One home, but users of the plugin install have to migrate.

## Recommendation

Option 1, depend at a pinned commit:

- It keeps one home for the guidance skills, which is where the README already says they live.
- The tool names already avoid each other.
- The cost is a single rename.

Rename this distribution's skill to `ism-controls-oscal`. It is the one with the distinct behaviour (live OSCAL). The pack's name is already in users' muscle memory.

## Consequences if accepted

- `install/bootstrap.sh` installs the pack at the pinned SHA, and `hermes profile update` bumps the pin through the existing dependency bump workflow.
- CI adds a check that skill names do not collide with the pinned pack's skill list. The list is recorded in the repo at the pinned SHA, so CI needs no network.
- `essential-eight-assessor` gets a note in the pack pointing to `essentials-assessment` for ASD Essentials.
- Until this is accepted, no code changes. This ADR only records the facts and the recommendation.
