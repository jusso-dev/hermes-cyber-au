---
key: "epic-docs"
title: "Epic: Documentation"
labels: ["type:epic", "area:docs", "priority:p1"]
milestone: "v0.1 MVP"
parent: "roadmap"
---
## Outcome
Docs site, quick start, generated connector and skill references, data licensing, contribution and security policy.

## Sub-issues
Linked as GitHub sub-issues. Checklist mirrors them by milestone.

### v0.1 MVP
- [ ] {{ref:docs-site}} Docs: Docs structure and site (MkDocs Material) published from docs/ (p1)
- [ ] {{ref:docs-quickstart}} Docs: Quick start: install, add keys, first triage, first briefing in 15 minutes (p0)
- [ ] {{ref:docs-connector-reference}} Docs: Generated connector reference pages and README connector table (p1)
- [ ] {{ref:docs-data-licensing}} Docs: Data sources, licences and attribution page (p0)
- [ ] {{ref:docs-contributing-security}} Docs: CONTRIBUTING, SECURITY policy, code of conduct, issue and PR templates (p1)

### v0.2
- [ ] {{ref:docs-skill-reference}} Docs: Skill reference pages with worked examples (p2)

## Definition of done
- [ ] Every sub-issue closed or moved to a later milestone with a reason.
- [ ] Docs updated for anything user-visible.
- [ ] Security review against `docs/security/threat-model.md`.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
