---
key: "skill-standards-evals"
title: "Skill authoring standard and offline eval harness"
labels: ["type:task", "area:skills", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-skills"
---
## Outcome
Every skill follows one standard and is tested by an offline eval harness that replays recorded connector fixtures.

## In scope
- `docs/skills/STANDARD.md`: frontmatter fields used (from [`website/docs/developer-guide/creating-skills.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/developer-guide/creating-skills.md)), section order, citation format (`Source: <name>, <version>, retrieved <date>`), defanging rules, untrusted content rule, proposal wording for any action, Australian English.
- `tests/skills/harness.py`: loads `evals.yaml`, starts connectors in `CYBERAU_OFFLINE=1` with fixtures, runs `hermes -p <test-profile> chat -q` (or the documented non-interactive equivalent) per case, and scores required facts, forbidden claims and expected tool calls.
- Model matrix configurable by env (`CYBERAU_EVAL_MODELS`), skipped in CI when no provider key is present; a deterministic structural check always runs.
- Results written to `tests/skills/results/<date>.json` (gitignored) and summarised in the PR.

## Acceptance criteria
- [ ] Harness runs one sample skill end to end offline.
- [ ] Structural checks (frontmatter, sections, references exist, no em dashes) run in `ci.yml` with no model key.
- [ ] An eval can assert that a tool was not called (used by injection cases).

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
