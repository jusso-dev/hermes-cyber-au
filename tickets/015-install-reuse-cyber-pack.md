---
key: "install-reuse-cyber-pack"
title: "Decide how to reuse the existing hermes-cyber-au guidance pack in jusso-dev/hermes-skills"
labels: ["type:task", "area:install", "area:skills", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-install"
---
## Outcome
A written decision, and the matching code change, on whether this distribution depends on, vendors or replaces the existing Australian cyber guidance pack.

## Context
The public pack at https://github.com/jusso-dev/hermes-skills/tree/main/plugins/hermes-cyber-au already ships ISM lookup, Essential Eight assessment, incident response, threat intel, Sentinel, CloudWatch and detection engineering skills, an allowlisted knowledge snapshot and an eval set. It installs with `hermes plugins install jusso-dev/hermes-skills/plugins/hermes-cyber-au`. Duplicating it would split fixes across two places.

## Options to evaluate
1. Depend: bootstrap installs that plugin at a pinned ref; this distribution adds connectors, store, routines and new skills.
2. Vendor: copy the skills in at a pinned commit with a sync script.
3. Replace: migrate the pack here and mark the old one as superseded.

## Acceptance criteria
- [ ] ADR at `docs/adr/0001-reuse-guidance-pack.md` with the choice and reasons (tool name clashes, licence MIT vs Apache-2.0 compatibility, update cadence).
- [ ] No duplicate skill names between the two packs once installed together (`skills_list` check in CI).
- [ ] Tool name collisions (`cyber_au_*` in the pack vs `intel_*` here) checked and documented.

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
