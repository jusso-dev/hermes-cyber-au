---
key: "epic-connectors"
title: "Epic: Connectors and the shared connector library"
labels: ["type:epic", "area:connectors", "priority:p0"]
milestone: "v0.1 MVP"
parent: "roadmap"
---
## Outcome
A shared HTTP client with egress policy, caching and rate limiting, plus one read-only MCP connector per source in the inventory.

## Sub-issues
Linked as GitHub sub-issues. Checklist mirrors them by milestone.

### v0.1 MVP
- [ ] {{ref:conn-shared-lib}} Shared connector library: HTTP client, egress allowlist, cache, rate limiter, result envelope (p0)
- [ ] {{ref:conn-scaffold-contract}} Connector scaffold generator and contract test suite (p1)
- [ ] {{ref:conn-feed-catalogue}} Feed catalogue feeds/catalogue.yaml: every source, URL, format, auth, licence, cadence (p1)
- [ ] {{ref:conn-asd-acsc}} Connector: ASD's ACSC alerts, advisories and publications (`asd`) (p0)
- [ ] {{ref:conn-asd-ism}} Connector: Information Security Manual (ISM) OSCAL catalogue (`ism`) (p0)
- [ ] {{ref:conn-asd-essentials}} Connector: Essential Eight and ASD Essentials (`e8`) (p0)
- [ ] {{ref:conn-cisa-kev}} Connector: CISA Known Exploited Vulnerabilities (`kev`) (p0)
- [ ] {{ref:conn-first-epss}} Connector: FIRST EPSS (`epss`) (p0)
- [ ] {{ref:conn-nvd}} Connector: NIST National Vulnerability Database (`nvd`) (p0)
- [ ] {{ref:conn-cloudflare-radar}} Connector: Cloudflare Radar via Cloudflare's unified MCP server (`cloudflare_radar`) (p1)
- [ ] {{ref:conn-auscert}} Connector: AusCERT public security bulletins (`auscert`) (p1)
- [ ] {{ref:conn-abusech}} Connector: abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker) (`abusech`) (p1)
- [ ] {{ref:conn-mitre-attack}} Connector: MITRE ATT&CK (STIX 2.1) (`attack`) (p1)

### v0.2
- [ ] {{ref:conn-osv}} Connector: OSV.dev open source vulnerabilities (`osv`) (p2)
- [ ] {{ref:conn-otx}} Connector: AlienVault OTX (`otx`) (p2)
- [ ] {{ref:conn-greynoise}} Connector: GreyNoise Community (`greynoise`) (p2)
- [ ] {{ref:conn-shodan-internetdb}} Connector: Shodan InternetDB (`internetdb`) (p2)
- [ ] {{ref:conn-sigma}} Connector: SigmaHQ detection rules (`sigma`) (p1)
- [ ] {{ref:conn-crtsh}} Connector: crt.sh certificate transparency (`crtsh`) (p3)
- [ ] {{ref:conn-au-regulatory}} Connector: Australian reporting obligations (OAIC NDB, SOCI, ransomware payments) (`aureg`) (p1)
- [ ] {{ref:conn-junction}} Connector: Junction (Microsoft Graph, Defender, Sentinel) (`junction`) (p2)
- [ ] {{ref:conn-m365-secure}} Integration: M365-Secure assessment reports (p2)

### v1.0
- [ ] {{ref:conn-brolga}} Connector: Brolga threat intel context engine (`brolga`) (p3)
- [ ] {{ref:conn-threatsieve}} Connector: ThreatSieve (`threatsieve`) (p3)

## Definition of done
- [ ] Every sub-issue closed or moved to a later milestone with a reason.
- [ ] Docs updated for anything user-visible.
- [ ] Security review against `docs/security/threat-model.md`.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
