---
key: "docs-data-licensing"
title: "Docs: Data sources, licences and attribution page"
labels: ["type:docs", "area:docs", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-docs"
---
## Outcome
Data sources, licences and attribution page.
## In scope
`docs/reference/data-sources.md`: for each source the licence or terms, required attribution text (NVD notice, MITRE ATT&CK, Sigma DRL 1.1, Cloudflare Radar, abuse.ch fair use, OTX terms, ASD content), commercial use notes, and how the distribution complies. `NOTICE` file updated to match.

## Acceptance criteria
- [ ] Every connector's `SOURCE.md` terms line links to this page.
- [ ] Each licence statement links to the upstream terms page and records the date it was checked.

## Constraints
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`).

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
