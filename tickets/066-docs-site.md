---
key: "docs-site"
title: "Docs: Docs structure and site (MkDocs Material) published from docs/"
labels: ["type:docs", "area:docs", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-docs"
---
## Outcome
Docs structure and site (MkDocs Material) published from docs/.
## In scope
- `mkdocs.yml`, `docs/index.md`, sections: Getting started, Skills, Connectors, Routines, Intel store, Security, Operations, Contributing, Reference.
- Australian English spell check (`codespell` with an en-AU word list) and the house style check (no em dashes, no emojis).
- Published to GitHub Pages by a docs job (proposed YAML added to `ci.yml` in the workflows ticket).

## Acceptance criteria
- [ ] `mkdocs build --strict` passes.
- [ ] Every page has an owner ticket and a last-verified date.

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
