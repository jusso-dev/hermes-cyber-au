---
key: "docs-skill-reference"
title: "Docs: Skill reference pages with worked examples"
labels: ["type:docs", "area:docs", "priority:p2"]
milestone: "v0.2"
parent: "epic-docs"
---
## Outcome
Skill reference pages with worked examples.
## In scope
One page per skill: when to use it, inputs, outputs, an end-to-end example from the eval set with real (fixture) output, limits.

## Acceptance criteria
- [ ] Examples are produced by the eval harness, not hand-written.

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
