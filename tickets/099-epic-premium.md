---
key: "epic-premium"
title: "Epic: Premium and commercial intel feeds"
labels: ["type:epic", "area:premium-feeds", "area:connectors", "priority:p2"]
milestone: "v0.2"
parent: "roadmap"
---
## Outcome
Paid, bring-your-own-licence feeds on Australian organisations (dark web and leak sites, ransomware victims, infostealer and breach exposure, brand and attack surface) behind one interface with terms flags, budgets and privacy handling, plus a free AU ransomware victim tracker, an AU org exposure skill and alert routine, and wiring into briefings and incident skills.

## Sub-issues
Linked as GitHub sub-issues. Checklist mirrors them by milestone.

### v0.2
- [ ] {{ref:premium-interface}} Design: common premium-connector interface (licence keys, terms flags, quota guardrails, exposure records, privacy) (p1)
- [ ] {{ref:premium-org-exposure}} Skill and routine: AU org exposure query and alert watch for the user's own domains, ABNs and brands (p1)
- [ ] {{ref:premium-wiring}} Wire premium exposure findings into the daily briefing, incident triage and breach notification skills (p2)
- [ ] {{ref:premium-hudson-rock}} Premium connector: Hudson Rock Cavalier (infostealer exposure by domain) (`hudsonrock`) (p2)
- [ ] {{ref:premium-spycloud}} Premium connector: SpyCloud Enterprise Protection (breach and malware exposure on a watchlist) (`spycloud`) (p2)
- [ ] {{ref:premium-upguard}} Premium connector: UpGuard CyberRisk (identity breaches, data leaks and typosquats; Australian vendor) (`upguard`) (p2)
- [ ] {{ref:premium-ransomware-live}} Connector (free): ransomware.live victim tracker (free, filter by country AU) (`ransomlive`) (p2)

### v1.0
- [ ] {{ref:premium-recorded-future}} Premium connector: Recorded Future (identity exposures and playbook alerts) (`recordedfuture`) (p3)
- [ ] {{ref:premium-flashpoint}} Premium connector: Flashpoint Ignite (compromised credentials and indicators) (`flashpoint`) (p3)
- [ ] {{ref:premium-intel471}} Premium connector: Intel 471 Titan (watchers, alerts, credentials and breach alerts) (`intel471`) (p3)
- [ ] {{ref:premium-google-ti-dtm}} Premium connector: Google Threat Intelligence Digital Threat Monitoring (formerly Mandiant) (`gtidtm`) (p3)
- [ ] {{ref:premium-crowdstrike-recon}} Premium connector: CrowdStrike Falcon Adversary Intelligence Recon (dark web monitoring notifications) (`csrecon`) (p3)
- [ ] {{ref:premium-socradar}} Premium connector: SOCRadar (company incidents: dark web, leaks, brand and attack surface) (`socradar`) (p3)
- [ ] {{ref:premium-darkowl}} Premium connector: DarkOwl Vision (dark web search) (`darkowl`) (p3)

## Definition of done
- [ ] Every sub-issue closed or moved to a later milestone with a reason.
- [ ] Docs updated for anything user-visible.
- [ ] Security review against `docs/security/threat-model.md`.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
