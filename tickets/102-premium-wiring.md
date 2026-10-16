---
key: "premium-wiring"
title: "Wire premium exposure findings into the daily briefing, incident triage and breach notification skills"
labels: ["type:feature", "area:routines", "area:skills", "area:premium-feeds", "priority:p2"]
milestone: "v0.2"
parent: "epic-premium"
---
## Outcome
Premium and free exposure findings show up where analysts already look: the daily briefing, incident triage and breach notification.

## Changes
- **Daily briefing** ({{ref:routine-daily-briefing}}, epic {{ref:epic-routines}}): new section "Exposure of our organisation" after ASD items, listing new findings from the `exposures` table since the last briefing, grouped by kind, with confidence labels. Omitted entirely when no premium vendor is enabled and the free tracker has nothing. Respects `share_outside_profile`.
- **Incident triage** ({{ref:skill-incident-triage}}): when the incident touches a watchlist domain, call `cyber_au_org_exposure` for that subject and the last 30 days, and add "related exposure" evidence to the triage summary. Infostealer findings for affected users raise the suggested priority.
- **Breach notification** ({{ref:skill-ndb-breach-notification}}): accept an `exposure` finding id as input. Prefill what is known (data classes, counts, first seen), mark what is unknown, and start the 30 day assessment reminder. It drafts; it never notifies anyone.
- **Executive briefing** ({{ref:skill-executive-briefing}}): one line on exposure trends, counts only.
- **STIX export** ({{ref:store-stix-export}}): exports only findings with `stix_exportable: true`.

## Tests
- Briefing snapshot tests with zero, one and many findings, and with a non-shareable finding and a non-owner delivery target.
- Triage and NDB skill eval cases using synthetic findings.

## Acceptance criteria
- [ ] All four outputs include exposure data from fixtures, with confidence labels and no secrets.
- [ ] With every premium vendor off, all outputs are unchanged from before this ticket.

## Constraints
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`).

Depends on {{ref:premium-interface}} and {{ref:premium-org-exposure}}.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
