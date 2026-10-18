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
- **#159 item 8:** Keep the distribution-owned `playbooks/` placeholder so later profile updates have a defined location. Content remains tracked by #167; no playbooks are claimed to ship yet.

## Planned features

The following issues remain planned work, not delivered functionality. P1 reliability, source truth, installation and inventory work comes first. Their existing issue acceptance criteria remain the implementation plan.

| Issue | Decision and prerequisite |
| --- | --- |
| #164 Live-model evaluation scorecard | Defer until an approved model account, cost budget and repeatable deterministic baseline are available. Keep score publication separate from local eval execution. |
| #165 Guided organisation setup | Defer until the organisation and inventory inputs have a stable contract. Do not infer or populate real customer details. |
| #166 Incident reporting obligations | Defer until reviewed legal-source dates, applicability rules and deadline tests are agreed. No automated regulatory submissions. |
| #167 Incident playbooks | Defer to a reviewed starter set with evidence capture and explicit approval boundaries. The empty directory is not a shipped playbook. |
| #168 Essentials evidence exports | Defer until evidence-register fields and document templates are agreed. Preserve source and freshness in later exports. |
| #169 SIEM hunt queries | Defer until target SIEM schemas and safe query fixtures are selected. Query generation does not authorise execution. |
| #170 Executive report templates | Defer until the source-backed briefing and incident data contract is stable. Templates must retain limitations and evidence references. |
| #171 Sector packs | Defer until the core profile and sector-specific obligations can be reviewed separately. |
| #172 Offline bundle | Defer until source redistribution terms, dependency locks and update verification are settled. Live-only sources must remain visibly unavailable offline. |
| #173 Briefing delivery | Defer until an explicit channel and recipient configuration is supplied. Delivery remains opt-in and draft-first. |

## Software monitoring scope

Inventory supports CSV and CycloneDX, including product versions and identifiers where supplied. Name or vendor matching against KEV produces candidates, not confirmed affected installations. A known installed version, a fresh source and an affected-version check are needed before claiming exposure. Empty inventory and missing or stale feeds must be visible; they are not an all-clear. Real company inventory is an operator input, never a bundled fixture.
