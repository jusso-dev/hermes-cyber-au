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
- [ ] {{ref:conn-virustotal}} Connector: VirusTotal via the official VirusTotal MCP server (`virustotal`) (p1)
- [ ] {{ref:conn-hibp}} Connector: Have I Been Pwned via the official HIBP MCP server (`hibp`) (p1)
- [ ] {{ref:conn-github-advisories}} Connector: GitHub Advisory Database via the GitHub MCP server (`ghsa`) (p1)

### v0.2
- [ ] {{ref:conn-osv}} Connector: OSV.dev open source vulnerabilities (`osv`) (p2)
- [ ] {{ref:conn-otx}} Connector: AlienVault OTX (`otx`) (p2)
- [ ] {{ref:conn-greynoise}} Connector: GreyNoise Community (`greynoise`) (p2)
- [ ] {{ref:conn-shodan-internetdb}} Connector: Shodan InternetDB (`internetdb`) (p2)
- [ ] {{ref:conn-sigma}} Connector: SigmaHQ detection rules (`sigma`) (p1)
- [ ] {{ref:conn-crtsh}} Connector: crt.sh certificate transparency (`crtsh`) (p2)
- [ ] {{ref:conn-au-regulatory}} Connector: Australian reporting obligations (OAIC NDB, SOCI, ransomware payments) (`aureg`) (p1)
- [ ] {{ref:conn-junction}} Connector: Junction (Microsoft Graph, Defender, Sentinel) (`junction`) (p2)
- [ ] {{ref:conn-m365-secure}} Integration: M365-Secure assessment reports (p2)
- [ ] {{ref:conn-taxii-ctis}} Connector: Generic TAXII 2.1 reader for ASD CTIS and other TAXII sources (`taxii`) (p2)
- [ ] {{ref:conn-ncsc-nz}} Connector: NCSC NZ alerts (formerly CERT NZ) (`ncscnz`) (p2)
- [ ] {{ref:conn-cloudflare-urlscanner}} Connector: Cloudflare URL Scanner (unlisted scans, approval-gated) (`cfscan`) (p2)
- [ ] {{ref:conn-cve-program}} Connector: CVE Program records (CVE Services API and cvelistV5) (`cve`) (p2)
- [ ] {{ref:conn-abuseipdb}} Connector: AbuseIPDB IP reputation (`abuseipdb`) (p2)
- [ ] {{ref:conn-spamhaus-drop}} Connector: Spamhaus DROP, DROPv6 and ASN-DROP (`drop`) (p2)

### v1.0
- [ ] {{ref:conn-brolga}} Connector: Brolga threat intel context engine (`brolga`) (p3)
- [ ] {{ref:conn-threatsieve}} Connector: ThreatSieve (`threatsieve`) (p3)
- [ ] {{ref:conn-irap}} Connector: IRAP guidance (`irap`) (p3)
- [ ] {{ref:conn-pspf}} Connector: Protective Security Policy Framework (PSPF) (`pspf`) (p3)
- [ ] {{ref:conn-scamwatch}} Connector: Scamwatch alerts (`scamwatch`) (p3)
- [ ] {{ref:conn-datagov-au}} Connector: data.gov.au (CKAN) (`datagov`) (p3)
- [ ] {{ref:conn-auscert-member}} Connector: AusCERT member URL feed (AusMISP goes through the MISP connector) (`auscertm`) (p3)
- [ ] {{ref:conn-asd-blueprint}} Connector: ASD Blueprint for Secure Cloud (`blueprint`) (p3)
- [ ] {{ref:conn-phishtank}} Connector: PhishTank verified phishing URLs (`phish`) (p3)
- [ ] {{ref:conn-openphish}} Connector: OpenPhish community feed (`phish`) (p3)
- [ ] {{ref:conn-misp}} Connector: MISP via the official MISP MCP server, for your own instance or AusMISP (`misp`) (p3)
- [ ] {{ref:conn-opencti}} Connector: OpenCTI (your own instance) (`opencti`) (p3)

## Definition of done
- [ ] Every sub-issue closed or moved to a later milestone with a reason.
- [ ] Docs updated for anything user-visible.
- [ ] Security review against `docs/security/threat-model.md`.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
