---
key: "epic-install"
title: "Epic: Install and bootstrap"
labels: ["type:epic", "area:install", "priority:p0"]
milestone: "v0.1 MVP"
parent: "roadmap"
---
## Outcome
One-command install of Hermes plus the cyber-au profile distribution, Docker image, doctor, plugin skeleton and the update path.

## Sub-issues
Linked as GitHub sub-issues. Checklist mirrors them by milestone.

### v0.1 MVP
- [ ] {{ref:install-distribution-skeleton}} Distribution skeleton: distribution.yaml, SOUL.md, config.yaml, .env.template, .gitignore (p0)
- [ ] {{ref:install-bootstrap}} install/install.sh and bootstrap: one command from bare machine to working profile (p0)
- [ ] {{ref:install-docker}} Docker image: FROM nousresearch/hermes-agent with the distribution preinstalled (p1)
- [ ] {{ref:install-doctor}} `hermes cyber-au doctor`: health check for profile, plugin, connectors, store and routines (p1)
- [ ] {{ref:install-plugin-skeleton}} Native plugin skeleton `plugins/cyber-au` (plugin.yaml, register(ctx), tools, hooks) (p0)
- [ ] {{ref:install-reuse-cyber-pack}} Decide how to reuse the existing hermes-cyber-au guidance pack in jusso-dev/hermes-skills (p1)

### v0.2
- [ ] {{ref:install-update-path}} Update and pinning path: hermes profile update, MCP venv refresh, migrations, rollback (p1)

## Definition of done
- [ ] Every sub-issue closed or moved to a later milestone with a reason.
- [ ] Docs updated for anything user-visible.
- [ ] Security review against `docs/security/threat-model.md`.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
