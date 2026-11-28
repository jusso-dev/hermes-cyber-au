# October 2026 review decisions

Recorded 18 October 2026 for [review epic #174](https://github.com/jusso-dev/hermes-cyber-au/issues/174). This page records scope and remaining work; it is not a release or deployment announcement.

## Reference data and bootstrap

- **#143:** ISM and Essential Eight refresh from their supported upstream sources. Australian reporting obligations remain reviewed reference data: there is no supported automatic fetch adapter. The scheduled workflow preserves their retrieval dates rather than relabelling an offline copy as newly fetched.
- **#154:** Bootstrap initialises the intel store and imports a KEV snapshot when present. ISM and Essential Eight reference files are validated and read by their connectors. ATT&CK is queried live. The intel schema has no framework-control table, so bootstrap does not claim to insert Essential Eight or ATT&CK rows. A future searchable framework store requires a separate schema design.

## Checks and publication

- **#156:** The private-name checker warns when its hash list is empty, and supports an explicit strict check and hidden-input name registration. No private names were supplied for this review. Do not invent names or claim the empty list protects them. Provisioning the list remains open.
- **#157:** Strict documentation builds and a downloadable CI artefact are the deliverable here. Public Pages publication remains open until its hosting and publication are configured. A successful local build does not mean the site is published.
- **#159 item 4:** Keep truthful pre-release wording until the first release exists. Update the repository description, README and roadmap together at that release.
- **#159 item 7:** Keep `tickets/`, `tools/tickets/` and `tools/issues/` as development planning provenance. They describe plans, not implemented capabilities. The application image excludes the ticket tree.
- **#159 item 8:** `playbooks/` stays distribution-owned. It now ships the #167 starter set of seven playbooks and a README, so profile updates replace them like other distribution files. Copy a playbook before tailoring it.

## Planned features

The following issues were planned work at the review. Rows marked delivered say what shipped; the rest are not delivered functionality. P1 reliability, source truth, installation and inventory work comes first. Their existing issue acceptance criteria remain the implementation plan.

| Issue | Decision and prerequisite |
| --- | --- |
| #164 Live-model evaluation scorecard | Defer until an approved model account, cost budget and repeatable deterministic baseline are available. Keep score publication separate from local eval execution. |
| #165 Guided organisation setup | Defer until the organisation and inventory inputs have a stable contract. Do not infer or populate real customer details. |
| #166 Incident reporting obligations | Delivered. `mcp/au-regulatory` snapshot `obligations-2026-11-28.json` has 11 rules (ransomware payment, SOCI 12 and 72 hour, APRA CPS 234 paragraphs 35 and 36, NDB assessment and statement, voluntary ASD report, Cyber Security Act Part 4 sharing, and two limited use notes), each with a source, a last reviewed date and a verification status, checked against the Register and regulator pages on 2026-11-28. The ASD limited use note is marked partial: the Intelligence Services Act text was not fetched. A pure engine (`aureg_check` tool and `skills/reporting-obligations`) returns applicable obligations, Sydney deadlines, recipients, sources, draft fields and a countdown. Business days do not skip public holidays, so the date shown is never later than the real deadline. Evals cover 13 sector scenarios. Nothing is submitted. Not legal advice. Rule data needs review again before 2027-05-27, when the 180 day snapshot limit refuses it. |
| #167 Incident playbooks | Delivered. Seven playbooks in `playbooks/` (business email compromise, ransomware, phishing, lost or stolen device, suspected data breach, compromised cloud admin account, third-party breach), each with phases, decisions, evidence to collect, who to tell, approval boundaries (the assistant proposes, a named person acts) and a link to the obligations checker. `skills/incident-playbook` walks a playbook and keeps an append-only timeline; its eval walks the ransomware playbook end to end. Playbooks pass the house style check. |
| #168 Essentials evidence exports | Defer until evidence-register fields and document templates are agreed. Preserve source and freshness in later exports. |
| #169 SIEM hunt queries | Defer until target SIEM schemas and safe query fixtures are selected. Query generation does not authorise execution. |
| #170 Executive report templates | Defer until the source-backed briefing and incident data contract is stable. Templates must retain limitations and evidence references. |
| #171 Sector packs | Defer until the core profile and sector-specific obligations can be reviewed separately. |
| #172 Offline bundle | Defer until source redistribution terms, dependency locks and update verification are settled. Live-only sources must remain visibly unavailable offline. |
| #173 Briefing delivery | Defer until an explicit channel and recipient configuration is supplied. Delivery remains opt-in and draft-first. |

## Software monitoring scope

Inventory supports CSV and CycloneDX, including product versions and identifiers where supplied. Name or vendor matching against KEV produces candidates, not confirmed affected installations. A known installed version, a fresh source and an affected-version check are needed before claiming exposure. Empty inventory and missing or stale feeds must be visible; they are not an all-clear. Real company inventory is an operator input, never a bundled fixture.
