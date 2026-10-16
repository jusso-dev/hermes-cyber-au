---
key: "roadmap"
title: "Roadmap: hermes-cyber-au, a Hermes Agent distribution for Australian cyber security teams"
labels: ["roadmap", "type:docs", "area:docs", "priority:p0"]
milestone: null
parent: null
---
## What this is
`hermes-cyber-au` is a planned Hermes Agent profile distribution for Australian cyber security teams. One install gives an analyst ASD guidance (ISM, Essential Eight, ASD Essentials), Australian and global threat intel connectors, a local intel store, daily briefings, and skills for triage, enrichment, vulnerability prioritisation, phishing, hunting, NDB and SOCI reporting and executive briefings.

Status: planned. This repository holds the plan as issues. No code has shipped yet.

## How it fits Hermes
It is a profile distribution (`distribution.yaml` at the repo root), installed with `hermes profile install github.com/jusso-dev/hermes-cyber-au --alias` and updated with `hermes profile update`. It ships a native plugin (`plugins/cyber-au`), stdio MCP connectors (`mcp/`), skills, paused cron jobs and scripts. Verified structure notes: `docs/research/hermes-structure.md`, checked against NousResearch/hermes-agent `43faacf` (v0.22.2).

## Milestones
- **v0.1 MVP**: install and doctor, shared connector library, ASD, ISM, Essential Eight and Essentials, KEV, EPSS, NVD, abuse.ch, ATT&CK connectors, the eleven skills at first quality, intel store with STIX export, daily briefing, core security controls, CI and data workflows.
- **v0.2**: Cloudflare Radar, AusCERT, OTX, GreyNoise, InternetDB, OSV, Sigma, crt.sh, AU obligations data, Junction and M365-Secure integrations, watchlists, retention, update path, supply chain, weekly releases.
- **v1.0**: optional Brolga and ThreatSieve bridges, DuckDB and MISP exports, Windows installer, hardened evals across model providers.

## Epics
- [ ] {{ref:epic-install}} Epic: Install and bootstrap
- [ ] {{ref:epic-connectors}} Epic: Connectors and the shared connector library
- [ ] {{ref:epic-skills}} Epic: Skills for Australian security teams
- [ ] {{ref:epic-intel-store}} Epic: Local threat intel store with dedupe and STIX 2.1 export
- [ ] {{ref:epic-routines}} Epic: Daily briefing and scheduled routines
- [ ] {{ref:epic-security}} Epic: Security of the agent itself
- [ ] {{ref:epic-docs}} Epic: Documentation
- [ ] {{ref:epic-ci}} Epic: GitHub Actions, data automation and releases

## Principles
- Read-only by default. The agent proposes; people act.
- Feed content is data, never instructions.
- Every claim carries a source, version and date. "I don't know" beats a guess.
- Works with zero API keys; each key adds sources.
- Australian English, plain language.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
