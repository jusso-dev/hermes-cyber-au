---
key: "docs-quickstart"
title: "Docs: Quick start: install, add keys, first triage, first briefing in 15 minutes"
labels: ["type:docs", "area:docs", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-docs"
---
## Outcome
Quick start: install, add keys, first triage, first briefing in 15 minutes.
## In scope
`docs/getting-started/quickstart.md`: install (`install.sh` or `hermes profile install github.com/jusso-dev/hermes-cyber-au --alias`), `cp .env.EXAMPLE .env`, which free keys to get first (abuse.ch, NVD), `cyber-au chat`, run `incident-triage` on the bundled sample alert, resume the morning briefing job.

## Acceptance criteria
- [ ] Followed verbatim on a clean VM by someone who did not write it; time recorded.
- [ ] Every command output pasted from a real run against Hermes v0.22.2.

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
