---
key: "epic-security"
title: "Epic: Security of the agent itself"
labels: ["type:epic", "area:security", "priority:p0"]
milestone: "v0.1 MVP"
parent: "roadmap"
---
## Outcome
Threat model, secrets handling, prompt injection defences for feed content, egress allowlist, audit log and supply chain.

## Sub-issues
Linked as GitHub sub-issues. Checklist mirrors them by milestone.

### v0.1 MVP
- [ ] {{ref:sec-threat-model}} Threat model for the agent itself (p0)
- [ ] {{ref:sec-secrets}} Secrets handling: env placeholders only, redaction everywhere, secret scanning in CI (p0)
- [ ] {{ref:sec-prompt-injection}} Prompt injection defences for feed content (p0)
- [ ] {{ref:sec-egress}} Egress allowlist: connectors, web tools and sandbox (p0)
- [ ] {{ref:sec-audit-log}} Tamper-evident audit log of tool calls, approvals and exports (p0)

### v0.2
- [ ] {{ref:sec-supply-chain}} Supply chain: pinned deps, SBOM, provenance, signed releases, update review (p1)

## Definition of done
- [ ] Every sub-issue closed or moved to a later milestone with a reason.
- [ ] Docs updated for anything user-visible.
- [ ] Security review against `docs/security/threat-model.md`.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
