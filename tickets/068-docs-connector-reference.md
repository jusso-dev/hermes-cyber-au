---
key: "docs-connector-reference"
title: "Docs: Generated connector reference pages and README connector table"
labels: ["type:docs", "area:docs", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-docs"
---
## Outcome
Generated connector reference pages and README connector table.
## In scope
- `tools/build_connector_docs.py` renders `docs/connectors/<key>.md` from `SOURCE.md`, tool input schemas and `feeds/catalogue.yaml`.
- Same script renders the README connector table between `<!-- connectors:start -->` and `<!-- connectors:end -->`.
- CI fails when generated files are stale.

## Acceptance criteria
- [ ] Every connector has a page with auth, env vars, rate limits, cache, tools and schemas, terms and attribution.

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
