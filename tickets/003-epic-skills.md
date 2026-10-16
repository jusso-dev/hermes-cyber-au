---
key: "epic-skills"
title: "Epic: Skills for Australian security teams"
labels: ["type:epic", "area:skills", "priority:p0"]
milestone: "v0.1 MVP"
parent: "roadmap"
---
## Outcome
Eleven skills from incident triage to SOCI reporting, built to one standard and tested offline.

## Sub-issues
Linked as GitHub sub-issues. Checklist mirrors them by milestone.

### v0.1 MVP
- [ ] {{ref:skill-standards-evals}} Skill authoring standard and offline eval harness (p0)
- [ ] {{ref:skill-incident-triage}} Skill: Incident triage (AU context) (`skills/incident-triage`) (p0)
- [ ] {{ref:skill-ioc-enrichment}} Skill: IOC enrichment (`skills/ioc-enrichment`) (p0)
- [ ] {{ref:skill-essentials-assessment}} Skill: Essential Eight and ASD Essentials assessment (`skills/essentials-assessment`) (p0)
- [ ] {{ref:skill-ism-control-lookup}} Skill: ISM control lookup (`skills/ism-control-lookup`) (p0)
- [ ] {{ref:skill-vuln-prioritisation}} Skill: Vulnerability prioritisation (KEV, EPSS, CVSS and Australian context) (`skills/vuln-prioritisation`) (p0)
- [ ] {{ref:skill-acsc-advisory-digest}} Skill: ASD's ACSC advisory digest (`skills/acsc-advisory-digest`) (p1)
- [ ] {{ref:skill-phishing-analysis}} Skill: Phishing analysis (`skills/phishing-analysis`) (p1)
- [ ] {{ref:skill-ndb-breach-notification}} Skill: Breach notification under the OAIC NDB scheme (`skills/ndb-breach-notification`) (p0)
- [ ] {{ref:skill-soci-reporting}} Skill: SOCI Act cyber incident reporting (`skills/soci-reporting`) (p1)
- [ ] {{ref:skill-executive-briefing}} Skill: Executive briefings (`skills/executive-briefing`) (p1)

### v0.2
- [ ] {{ref:skill-threat-hunting}} Skill: Threat hunting with Sigma and KQL (`skills/threat-hunting`) (p1)

## Definition of done
- [ ] Every sub-issue closed or moved to a later milestone with a reason.
- [ ] Docs updated for anything user-visible.
- [ ] Security review against `docs/security/threat-model.md`.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
