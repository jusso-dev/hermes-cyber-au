# hermes-cyber-au

A planned [Hermes Agent](https://github.com/NousResearch/hermes-agent) distribution for Australian cyber security teams.

Install it once and you get an analyst assistant that knows the ISM, the Essential Eight and the new ASD Essentials, reads ASD's ACSC and AusCERT as they publish, pulls in global threat intel, keeps a local intel store, and writes you a briefing before you've finished your coffee. It proposes actions. It doesn't take them.

> **Status: planned.** Nothing is implemented yet. This repository holds the design and the build plan as GitHub issues. Start with the roadmap issue, then the epics.

## What it will do

- **Triage incidents** with Australian context: ASD's ACSC categorisation, ATT&CK mapping, containment proposals, and a check for NDB, SOCI and ransomware payment reporting triggers.
- **Enrich indicators** across abuse.ch, OTX, GreyNoise, Shodan InternetDB, crt.sh and Cloudflare Radar, deduplicated into one verdict with sources.
- **Assess Essential Eight maturity and ASD Essentials progress** from evidence you supply, including M365-Secure reports. Both frameworks, because ASD is running them side by side during the transition.
- **Look up ISM controls** by id, keyword or baseline, from the release that was in force on the date you ask about. If a control isn't in the snapshot, it says "I don't know".
- **Prioritise vulnerabilities** with KEV, EPSS, CVSS, ASD and AusCERT mentions, your asset list, and Essential Eight patching timeframes.
- **Digest ASD's ACSC advisories** and AusCERT bulletins since the last digest, grouped by what to do today, this week, and what to know.
- **Analyse phishing**: headers, SPF, DKIM and DMARC, lookalike domains of Australian brands, hash lookups. No detonation.
- **Hunt with Sigma and KQL** for Microsoft Sentinel and Defender, with offline query checks.
- **Walk through an OAIC Notifiable Data Breach assessment** and draft the statement. A person submits it.
- **Decide SOCI Act reportability** and compute the 12 and 72 hour deadlines in Sydney time.
- **Write executive and board briefings** in plain Australian English.
- **Run routines**: hourly feed ingest, a 07:30 Sydney briefing, a KEV watch against your assets, and a weekly executive summary. All arrive paused so you choose what runs.

## How it fits together

| Piece | Where | What it is |
|---|---|---|
| Profile distribution | `distribution.yaml`, `SOUL.md`, `config.yaml` | Installed with `hermes profile install`, updated with `hermes profile update` |
| Skills | `skills/<name>/SKILL.md` | The eleven workflows above |
| Connectors | `mcp/<source>/` | Read-only stdio MCP servers on a shared HTTP client with an egress allowlist, caching and rate limiting |
| Plugin | `plugins/cyber-au/` | Intel store tools, audit log hooks, untrusted-content guards, the `cyber-au` command |
| Intel store | `plugin-data/cyber-au/intel.sqlite` | SQLite with canonical dedupe and STIX 2.1 export |
| Routines | `cron/jobs.json`, `scripts/` | Scheduled jobs, shipped paused |
| Automation | `ci/workflows/` | Proposed GitHub Actions: CI, nightly intel refresh, skill data regeneration, connector health, dependency and Hermes bumps, weekly releases |

The Hermes details behind this design (manifest fields, what an update replaces, MCP config, plugin hooks, cron rules) are written up with sources in [docs/research/hermes-structure.md](docs/research/hermes-structure.md).

## Planned install

```bash
# Once v0.1 ships. Not yet.
hermes profile install github.com/jusso-dev/hermes-cyber-au --alias
cp ~/.hermes/profiles/cyber-au/.env.EXAMPLE ~/.hermes/profiles/cyber-au/.env
cyber-au chat
```

It works with no API keys using public sources. Each free key you add (abuse.ch, NVD, OTX, GreyNoise, a Cloudflare Radar read token) turns on more sources.

## Connectors

<!-- connectors:start -->
| Connector | Server | Group | Auth | Default | Milestone | Status | Docs |
|---|---|---|---|---|---|---|---|
| ASD's ACSC alerts, advisories and publications | `asd` | Australian government | none | on | v0.1 MVP | planned | [docs/connectors/asd-acsc.md](docs/connectors/asd-acsc.md) |
| Information Security Manual (ISM) OSCAL catalogue | `ism` | Australian government | `GITHUB_TOKEN` (optional) | on | v0.1 MVP | planned | [docs/connectors/asd-ism.md](docs/connectors/asd-ism.md) |
| Essential Eight and ASD Essentials | `e8` | Australian government | none | on | v0.1 MVP | planned | https://www.cyber.gov.au/publication/what-is-the-essentials |
| CISA Known Exploited Vulnerabilities | `kev` | Vulnerability intelligence | none | on | v0.1 MVP | planned | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| FIRST EPSS | `epss` | Vulnerability intelligence | none | on | v0.1 MVP | planned | [docs/connectors/first-epss.md](docs/connectors/first-epss.md) |
| NIST National Vulnerability Database | `nvd` | Vulnerability intelligence | `NVD_API_KEY` (optional) | on | v0.1 MVP | planned | [docs/connectors/nvd.md](docs/connectors/nvd.md) |
| OSV.dev open source vulnerabilities | `osv` | Vulnerability intelligence | none | on | v0.2 | planned | https://google.github.io/osv.dev/api/ |
| Cloudflare Radar via Cloudflare's unified MCP server | `cloudflare_radar` | Internet and attack telemetry | `CLOUDFLARE_RADAR_API_TOKEN` (optional) | off: non-commercial terms, bring your own key | v0.1 MVP | planned | https://developers.cloudflare.com/radar/ |
| AusCERT public security bulletins | `auscert` | Australian community | none | on | v0.1 MVP | planned | https://www.auscert.org.au/ |
| abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker) | `abusech` | Global threat intelligence | `ABUSECH_AUTH_KEY` | off: non-commercial terms, bring your own key | v0.1 MVP | planned | [docs/connectors/abusech.md](docs/connectors/abusech.md) |
| AlienVault OTX | `otx` | Global threat intelligence | `OTX_API_KEY` | on | v0.2 | planned | [docs/connectors/otx.md](docs/connectors/otx.md) |
| GreyNoise Community | `greynoise` | Global threat intelligence | `GREYNOISE_API_KEY` (optional) | on | v0.2 | planned | https://docs.greynoise.io/ |
| Shodan InternetDB | `internetdb` | Global threat intelligence | none | on | v0.2 | planned | https://internetdb.shodan.io/ |
| MITRE ATT&CK (STIX 2.1) | `attack` | Frameworks | none | on | v0.1 MVP | planned | https://github.com/mitre-attack/attack-stix-data |
| SigmaHQ detection rules | `sigma` | Frameworks | `GITHUB_TOKEN` (optional) | on | v0.2 | planned | https://github.com/SigmaHQ/sigma |
| crt.sh certificate transparency | `crtsh` | Global threat intelligence | none | on | v0.2 | planned | https://crt.sh/ |
| Australian reporting obligations (OAIC NDB, SOCI, ransomware payments) | `aureg` | Australian government | none | on | v0.2 | planned | https://www.oaic.gov.au/privacy/notifiable-data-breaches |
| Junction (Microsoft Graph, Defender, Sentinel) | `junction` | Author's public tools | `JUNCTION_BIN` (optional) | on | v0.2 | planned | https://github.com/jusso-dev/junction |
| Brolga threat intel context engine | `brolga` | Author's public tools | `BROLGA_URL` (optional), `BROLGA_API_TOKEN` | on | v1.0 | planned | https://github.com/jusso-dev/Brolga |
| ThreatSieve | `threatsieve` | Author's public tools | `THREATSIEVE_URL` (optional), `THREATSIEVE_API_KEY` (optional) | on | v1.0 | planned | https://github.com/jusso-dev/ThreatSieve |
| M365-Secure assessment reports | `(none)` | Author's public tools | none | on | v0.2 | planned | https://github.com/jusso-dev/M365-Secure |
| VirusTotal via the official VirusTotal MCP server | `virustotal` | Global threat intelligence | `VIRUSTOTAL_API_KEY` | off: non-commercial terms, bring your own key | v0.1 MVP | planned | https://docs.virustotal.com/reference/overview |
| Have I Been Pwned via the official HIBP MCP server | `hibp` | Global threat intelligence | `HIBP_API_KEY` (optional) | on | v0.1 MVP | planned | https://haveibeenpwned.com/API/v3 |
| GitHub Advisory Database via the GitHub MCP server | `ghsa` | Vulnerability intelligence | `GITHUB_ADVISORY_TOKEN` (optional) | on | v0.1 MVP | planned | https://github.com/advisories |
| Generic TAXII 2.1 reader for ASD CTIS and other TAXII sources | `taxii` | Australian government | `TAXII_API_ROOT`, `TAXII_COLLECTION_ID`, `TAXII_USERNAME`, `TAXII_PASSWORD` | off: bring your own access | v0.2 | planned | https://www.cyber.gov.au/become-a-partner |
| NCSC NZ alerts (formerly CERT NZ) | `ncscnz` | Regional government | none | on | v0.2 | planned | https://www.ncsc.govt.nz/alerts/ |
| Cloudflare URL Scanner (unlisted scans, approval-gated) | `cfscan` | Internet and attack telemetry | `CLOUDFLARE_URLSCAN_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` | off: bring your own access | v0.2 | planned | https://developers.cloudflare.com/radar/investigate/url-scanner/ |
| CVE Program records (CVE Services API and cvelistV5) | `cve` | Vulnerability intelligence | none | on | v0.2 | planned | https://www.cve.org/ |
| AbuseIPDB IP reputation | `abuseipdb` | Global threat intelligence | `ABUSEIPDB_API_KEY` | on | v0.2 | planned | [docs/connectors/abuseipdb.md](docs/connectors/abuseipdb.md) |
| Spamhaus DROP, DROPv6 and ASN-DROP | `drop` | Global threat intelligence | none | on | v0.2 | planned | https://www.spamhaus.org/blocklists/do-not-route-or-peer/ |
| IRAP guidance | `irap` | Australian government | none | on | v1.0 | planned | https://www.cyber.gov.au/irap |
| Protective Security Policy Framework (PSPF) | `pspf` | Australian government | none | on | v1.0 | planned | https://www.protectivesecurity.gov.au/ |
| Scamwatch alerts | `scamwatch` | Australian government | none | on | v1.0 | planned | https://www.scamwatch.gov.au/ |
| data.gov.au (CKAN) | `datagov` | Australian government | none | on | v1.0 | planned | [docs/connectors/datagov-au.md](docs/connectors/datagov-au.md) |
| AusCERT member URL feed (AusMISP goes through the MISP connector) | `auscertm` | Australian community | `AUSCERT_URL_FEED`, `AUSCERT_FEED_TOKEN` (optional) | off: bring your own access | v1.0 | planned | https://auscert.org.au/services/threat-intelligence/ |
| ASD Blueprint for Secure Cloud | `blueprint` | Australian government | none | on | v1.0 | planned | [docs/connectors/asd-blueprint.md](docs/connectors/asd-blueprint.md) |
| PhishTank verified phishing URLs | `phish` | Global threat intelligence | `PHISHTANK_APP_KEY` (optional) | on | v1.0 | planned | https://phishtank.org/developer_info.php |
| OpenPhish community feed | `phish` | Global threat intelligence | none | on | v1.0 | planned | https://openphish.com/ |
| MISP via the official MISP MCP server, for your own instance or AusMISP | `misp` | CTI platforms | `MISP_URL`, `MISP_API_KEY` | off: bring your own access | v1.0 | planned | https://www.misp-project.org/ |
| OpenCTI (your own instance) | `opencti` | CTI platforms | `OPENCTI_URL`, `OPENCTI_TOKEN` | off: bring your own access | v1.0 | planned | https://docs.opencti.io/ |
| Hudson Rock Cavalier (infostealer exposure by domain) | `hudsonrock` | Credential and infostealer exposure | `HUDSONROCK_API_KEY` | off: paid, bring your own licence | v1.0 | planned | https://docs.hudsonrock.com/ |
| SpyCloud Enterprise Protection (breach and malware exposure on a watchlist) | `spycloud` | Credential and infostealer exposure | `SPYCLOUD_API_KEY` | off: paid, bring your own licence | v1.0 | planned | https://docs.spycloud.com/public-sc/docs/api-guidelines |
| UpGuard CyberRisk (identity breaches, data leaks and typosquats; Australian vendor) | `upguard` | Attack surface and brand monitoring | `UPGUARD_API_KEY` | off: paid, bring your own licence | v0.2 | planned | https://cyber-risk.upguard.com/api/docs |
| ransomware.live victim tracker (free, filter by country AU) | `ransomlive` | Ransomware victim monitoring (free) | `RANSOMWARE_LIVE_API_KEY` (optional) | off: free, victim data | v0.2 | planned | https://www.ransomware.live/apidocs |
| Recorded Future (identity exposure, dark web and ransomware brand alerts, domain abuse, risk lists, official MCP) | `recordedfuture` | Threat intelligence platforms | `RECORDED_FUTURE_API_TOKEN`, `RECORDED_FUTURE_ORG_ID` (optional), `RECORDED_FUTURE_MCP_CLIENT_ID` (optional), `RECORDED_FUTURE_MCP_CLIENT_SECRET` (optional) | off: paid, bring your own licence | v0.2 | planned | https://docs.recordedfuture.com/reference/get-started |
| Flashpoint Ignite (compromised credentials and indicators) | `flashpoint` | Threat intelligence platforms | `FLASHPOINT_API_TOKEN` | off: paid, bring your own licence | v1.0 | planned | https://docs.flashpoint.io/ |
| Intel 471 Titan (watchers, alerts, credentials and breach alerts) | `intel471` | Threat intelligence platforms | `INTEL471_EMAIL`, `INTEL471_API_KEY` | off: paid, bring your own licence | v1.0 | planned | https://github.com/intel471/titan-client-python |
| Google Threat Intelligence Digital Threat Monitoring (formerly Mandiant) | `gtidtm` | Dark web and leak monitoring | `GTI_API_KEY` | off: paid, bring your own licence | v1.0 | planned | https://gtidocs.virustotal.com/ |
| CrowdStrike Falcon Adversary Intelligence Recon (dark web monitoring notifications) | `csrecon` | Dark web and leak monitoring | `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL` (optional) | off: paid, bring your own licence | v1.0 | planned | https://developer.crowdstrike.com/api-reference/collections/recon/ |
| SOCRadar (company incidents: dark web, leaks, brand and attack surface) | `socradar` | Dark web and leak monitoring | `SOCRADAR_API_KEY`, `SOCRADAR_COMPANY_ID` | off: paid, bring your own licence | v1.0 | planned | https://socradar.io/socradar-apis/ |
| DarkOwl Vision (dark web search) | `darkowl` | Dark web and leak monitoring | `DARKOWL_PUBLIC_KEY`, `DARKOWL_PRIVATE_KEY` | off: paid, bring your own licence | v1.0 | planned | https://support.darkowl.com/knowledge-base/search-api-documentation |
| Flare threat exposure management (leaked credentials, stealer logs, leak and ransomware sites, dark web, official MCP) | `flare` | Dark web and leak monitoring | `FLARE_API_KEY`, `FLARE_TENANT_ID` (optional) | off: paid, bring your own licence | v0.2 | planned | https://api.docs.flare.io/introduction/getting-started |
<!-- connectors:end -->

Full detail, including what was verified and when: [docs/research/connectors.md](docs/research/connectors.md).

## Premium feeds (paid, bring your own licence)

Teams that already pay for commercial intel can plug it in. First up in v0.2 are Recorded Future (identity exposure, dark web and ransomware brand alerts, domain abuse) and Flare (leaked credentials, stealer logs, leak and ransomware sites), both with optional use of the vendor's own MCP server, plus UpGuard (identity breaches, data leaks and typosquats; an Australian vendor). Later connectors cover infostealer and breach exposure (Hudson Rock, SpyCloud) and more threat intel platforms with dark web and leak site monitoring (Flashpoint, Intel 471, Google Threat Intelligence DTM, CrowdStrike Recon, SOCRadar, DarkOwl). The free ransomware.live tracker adds leak site claims naming Australian organisations.

- Every premium connector is off by default. You bring your own licence key through the profile `.env`; nothing is bundled.
- Each vendor has terms flags: what may be cached, stored, exported as STIX or shared. Defaults are conservative until your contract says otherwise.
- Quota and budget limits stop runaway spend.
- Exposure data can contain personal information. It is redacted, kept for 90 days by default, and never sent anywhere automatically. Nothing contacts the OAIC, ASD, victims or vendors for you.
- An "AU org exposure" skill and a paused alert routine match findings against a watchlist of your own domains, ABNs and brands.

The rows marked "paid, bring your own licence" in the table above are these connectors.

## Safety

- Read-only by default. Anything that sends, blocks, posts or submits needs a person to approve it.
- Content from feeds is treated as data, never as instructions.
- Secrets live in your profile `.env` and are referenced as `${VAR}`. Nothing secret is shipped, logged or exported.
- Connectors can only reach the hosts listed for them.
- Every tool call is written to a hash-chained audit log.

## Not affiliated

This project is independent. It is not affiliated with or endorsed by the Australian Signals Directorate, the Australian Cyber Security Centre, the OAIC, the Cyber and Infrastructure Security Centre, Nous Research or any data provider. Its output is guidance, not legal advice or a formal assessment.

## Related projects

This repository used to hold a smaller Hermes skill and plugin pack for Australian cyber guidance. It is now a full Hermes profile distribution: connectors, a local intel store, scheduled routines and agent security controls, as well as skills. It is not a skill pack any more.

- **The earlier skill pack** is kept unchanged on the [`legacy-skills-pack`](https://github.com/jusso-dev/hermes-cyber-au/tree/legacy-skills-pack) branch and the [`legacy-skills-pack-final`](https://github.com/jusso-dev/hermes-cyber-au/releases/tag/legacy-skills-pack-final) tag (commit `02b500c49ca08f5d558107e58a42a9c68a617566`). If you installed it from this repository, pin to that commit, for example `hermes plugins install jusso-dev/hermes-cyber-au --force --ref 02b500c49ca08f5d558107e58a42a9c68a617566` (Hermes takes a full 40 character commit SHA for `--ref`), or move to the maintained copy below.
- [jusso-dev/hermes-skills](https://github.com/jusso-dev/hermes-skills): where the skill pack now lives and gets updates. Install it with `hermes plugins install jusso-dev/hermes-skills/plugins/hermes-cyber-au`. How this distribution reuses it is tracked in an issue.
- [AustralianCyberSecurityCentre/ism-oscal](https://github.com/AustralianCyberSecurityCentre/ism-oscal): ISM in OSCAL, the source for ISM and Essential Eight data.

## Licence

Apache License 2.0. See [LICENSE](LICENSE). Data from each source stays under that source's terms; see the data licensing issue and, once written, `docs/reference/data-sources.md`.
