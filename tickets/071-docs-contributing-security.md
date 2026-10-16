---
key: "docs-contributing-security"
title: "Docs: CONTRIBUTING, SECURITY policy, code of conduct, issue and PR templates"
labels: ["type:docs", "area:docs", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-docs"
---
## Outcome
CONTRIBUTING, SECURITY policy, code of conduct, issue and PR templates.
## In scope
- `CONTRIBUTING.md`: dev setup with uv, adding a connector (`cyberau-mcp new`), recording fixtures safely, house style.
- `SECURITY.md`: private vulnerability reporting through GitHub Security Advisories, supported versions, response targets.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- `.github/ISSUE_TEMPLATE/` (connector request, bug, skill request) and `PULL_REQUEST_TEMPLATE.md`. These are not workflow files, so the normal token can push them; confirm before relying on that.

## Acceptance criteria
- [ ] Private vulnerability reporting enabled on the repo (Justin, repo settings).

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
