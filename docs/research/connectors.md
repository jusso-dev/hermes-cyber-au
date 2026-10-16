# Connector inventory

Checked on 16 October 2026. The first 21 sources were compiled and verified for this plan. The rest were added from a second, independent inventory checked on the same date, for sources the first list did not cover. Sources with non-commercial terms (Cloudflare Radar, VirusTotal, abuse.ch) ship off by default and users bring their own key. Each connector ticket carries endpoints, auth, limits, terms and what was verified.

| Connector | Server | Group | Auth | Default | Milestone | Status | Docs |
|---|---|---|---|---|---|---|---|
| ASD's ACSC alerts, advisories and publications | `asd` | Australian government | none | on | v0.1 MVP | planned | https://www.cyber.gov.au/ |
| Information Security Manual (ISM) OSCAL catalogue | `ism` | Australian government | `GITHUB_TOKEN` (optional) | on | v0.1 MVP | planned | https://github.com/AustralianCyberSecurityCentre/ism-oscal |
| Essential Eight and ASD Essentials | `e8` | Australian government | none | on | v0.1 MVP | planned | https://www.cyber.gov.au/publication/what-is-the-essentials |
| CISA Known Exploited Vulnerabilities | `kev` | Vulnerability intelligence | none | on | v0.1 MVP | planned | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| FIRST EPSS | `epss` | Vulnerability intelligence | none | on | v0.1 MVP | planned | https://api.first.org/epss/ |
| NIST National Vulnerability Database | `nvd` | Vulnerability intelligence | `NVD_API_KEY` (optional) | on | v0.1 MVP | planned | https://nvd.nist.gov/developers/vulnerabilities |
| OSV.dev open source vulnerabilities | `osv` | Vulnerability intelligence | none | on | v0.2 | planned | https://google.github.io/osv.dev/api/ |
| Cloudflare Radar via Cloudflare's unified MCP server | `cloudflare_radar` | Internet and attack telemetry | `CLOUDFLARE_RADAR_API_TOKEN` (optional) | off: non-commercial terms, bring your own key | v0.1 MVP | planned | https://developers.cloudflare.com/radar/ |
| AusCERT public security bulletins | `auscert` | Australian community | none | on | v0.1 MVP | planned | https://www.auscert.org.au/ |
| abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker) | `abusech` | Global threat intelligence | `ABUSECH_AUTH_KEY` | off: non-commercial terms, bring your own key | v0.1 MVP | planned | https://abuse.ch/ |
| AlienVault OTX | `otx` | Global threat intelligence | `OTX_API_KEY` | on | v0.2 | planned | https://otx.alienvault.com/api |
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
| AbuseIPDB IP reputation | `abuseipdb` | Global threat intelligence | `ABUSEIPDB_API_KEY` | on | v0.2 | planned | https://docs.abuseipdb.com/ |
| Spamhaus DROP, DROPv6 and ASN-DROP | `drop` | Global threat intelligence | none | on | v0.2 | planned | https://www.spamhaus.org/blocklists/do-not-route-or-peer/ |
| IRAP guidance | `irap` | Australian government | none | on | v1.0 | planned | https://www.cyber.gov.au/irap |
| Protective Security Policy Framework (PSPF) | `pspf` | Australian government | none | on | v1.0 | planned | https://www.protectivesecurity.gov.au/ |
| Scamwatch alerts | `scamwatch` | Australian government | none | on | v1.0 | planned | https://www.scamwatch.gov.au/ |
| data.gov.au (CKAN) | `datagov` | Australian government | none | on | v1.0 | planned | https://data.gov.au/ |
| AusCERT member URL feed (AusMISP goes through the MISP connector) | `auscertm` | Australian community | `AUSCERT_URL_FEED`, `AUSCERT_FEED_TOKEN` (optional) | off: bring your own access | v1.0 | planned | https://auscert.org.au/services/threat-intelligence/ |
| ASD Blueprint for Secure Cloud | `blueprint` | Australian government | none | on | v1.0 | planned | https://blueprint.asd.gov.au/ |
| PhishTank verified phishing URLs | `phish` | Global threat intelligence | `PHISHTANK_APP_KEY` (optional) | on | v1.0 | planned | https://phishtank.org/developer_info.php |
| OpenPhish community feed | `phish` | Global threat intelligence | none | on | v1.0 | planned | https://openphish.com/ |
| MISP via the official MISP MCP server, for your own instance or AusMISP | `misp` | CTI platforms | `MISP_URL`, `MISP_API_KEY` | off: bring your own access | v1.0 | planned | https://www.misp-project.org/ |
| OpenCTI (your own instance) | `opencti` | CTI platforms | `OPENCTI_URL`, `OPENCTI_TOKEN` | off: bring your own access | v1.0 | planned | https://docs.opencti.io/ |
| Hudson Rock Cavalier (infostealer exposure by domain) | `hudsonrock` | Credential and infostealer exposure | `HUDSONROCK_API_KEY` | off: paid, bring your own licence | v0.2 | planned | https://docs.hudsonrock.com/ |
| SpyCloud Enterprise Protection (breach and malware exposure on a watchlist) | `spycloud` | Credential and infostealer exposure | `SPYCLOUD_API_KEY` | off: paid, bring your own licence | v0.2 | planned | https://docs.spycloud.com/public-sc/docs/api-guidelines |
| UpGuard CyberRisk (identity breaches, data leaks and typosquats; Australian vendor) | `upguard` | Attack surface and brand monitoring | `UPGUARD_API_KEY` | off: paid, bring your own licence | v0.2 | planned | https://cyber-risk.upguard.com/api/docs |
| ransomware.live victim tracker (free, filter by country AU) | `ransomlive` | Ransomware victim monitoring (free) | `RANSOMWARE_LIVE_API_KEY` (optional) | off: free, victim data | v0.2 | planned | https://www.ransomware.live/apidocs |
| Recorded Future (identity exposures and playbook alerts) | `recordedfuture` | Threat intelligence platforms | `RECORDED_FUTURE_API_TOKEN` | off: paid, bring your own licence | v1.0 | planned | https://docs.recordedfuture.com/reference/get-started |
| Flashpoint Ignite (compromised credentials and indicators) | `flashpoint` | Threat intelligence platforms | `FLASHPOINT_API_TOKEN` | off: paid, bring your own licence | v1.0 | planned | https://docs.flashpoint.io/ |
| Intel 471 Titan (watchers, alerts, credentials and breach alerts) | `intel471` | Threat intelligence platforms | `INTEL471_EMAIL`, `INTEL471_API_KEY` | off: paid, bring your own licence | v1.0 | planned | https://github.com/intel471/titan-client-python |
| Google Threat Intelligence Digital Threat Monitoring (formerly Mandiant) | `gtidtm` | Dark web and leak monitoring | `GTI_API_KEY` | off: paid, bring your own licence | v1.0 | planned | https://gtidocs.virustotal.com/ |
| CrowdStrike Falcon Adversary Intelligence Recon (dark web monitoring notifications) | `csrecon` | Dark web and leak monitoring | `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL` (optional) | off: paid, bring your own licence | v1.0 | planned | https://developer.crowdstrike.com/api-reference/collections/recon/ |
| SOCRadar (company incidents: dark web, leaks, brand and attack surface) | `socradar` | Dark web and leak monitoring | `SOCRADAR_API_KEY`, `SOCRADAR_COMPANY_ID` | off: paid, bring your own licence | v1.0 | planned | https://socradar.io/socradar-apis/ |
| DarkOwl Vision (dark web search) | `darkowl` | Dark web and leak monitoring | `DARKOWL_PUBLIC_KEY`, `DARKOWL_PRIVATE_KEY` | off: paid, bring your own licence | v1.0 | planned | https://support.darkowl.com/knowledge-base/search-api-documentation |

## Details

### ASD's ACSC alerts, advisories and publications
- Endpoints: `GET` https://www.cyber.gov.au/rss/alerts; `GET` https://www.cyber.gov.au/rss/advisories; `GET` https://www.cyber.gov.au/rss/publications; `GET` https://www.cyber.gov.au/rss/threats; `GET` https://www.cyber.gov.au/rss/news; `GET` https://www.cyber.gov.au/<item path>
- Auth: None.
- Rate limits: No published limit. Self-imposed: one request per feed per 10 minutes, item pages at most 1 request every 5 seconds. The CDN is known to stall some egress paths, so use a 60 second timeout, 3 retries with backoff and fall back to the last good snapshot.
- Terms: Check the cyber.gov.au copyright page for the current licence and attribution wording before shipping snapshots. Keep the attribution string in `mcp/asd/SOURCE.md`.
- Verified: `/rss/alerts`, `/rss/advisories`, `/rss/publications`, `/rss/threats` listed by two independent feed directories. Direct fetch from the build box timed out, which matches the CDN note above.

### Information Security Manual (ISM) OSCAL catalogue
- Endpoints: `GET` https://api.github.com/repos/AustralianCyberSecurityCentre/ism-oscal/releases; `GET` https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal/<tag>/ISM_catalog.json; `GET` https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal/<tag>/ISM_<BASELINE>-baseline-resolved-profile_catalog.json
- Auth: None. Optional `GITHUB_TOKEN` raises the GitHub API limit from 60 to 5,000 requests an hour.
- Rate limits: GitHub API: 60 requests an hour unauthenticated. Raw downloads happen once per release.
- Terms: ISM content is published by ASD. Record the release tag, file SHA-256 and retrieval date for every answer.
- Verified: Repository is public, files listed via the GitHub contents API, releases `v2026.03.24`, `v2026.06.18`, `v2026.09.4` present.

### Essential Eight and ASD Essentials
- Endpoints: `GET` ISM OSCAL `ISM_E8_ML1/2/3-baseline-resolved-profile_catalog.json`; `GET` https://www.cyber.gov.au/publication/what-is-the-essentials; `GET` https://www.cyber.gov.au/publication/essentials-for-enterprise-it; `GET` https://www.cyber.gov.au/publication/essentials-for-cloud; `GET` https://www.asd.gov.au/news/2026-10-15-asd-essentials-evolving-our-approach-cyber-security-resilience
- Auth: None.
- Rate limits: Pages fetched only by the regeneration workflow, at most once a day, 1 request every 5 seconds.
- Terms: ASD content. Same attribution handling as the ASD connector.
- Verified: Launch notice and the enterprise IT and cloud chapter pages found on 16 October 2026. E8 ML baselines present in ISM OSCAL.

### CISA Known Exploited Vulnerabilities
- Endpoints: `GET` https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Auth: None.
- Rate limits: One full download per 6 hours. Conditional GET with ETag.
- Terms: US Government work. Cite CISA and the `dateAdded` field.
- Verified: JSON feed returned HTTP 200 on 16 October 2026.

### FIRST EPSS
- Endpoints: `GET` https://api.first.org/data/v1/epss?cve=<comma list>; `GET` Daily bulk CSV linked from https://www.first.org/epss/data
- Auth: None.
- Rate limits: 1,000 requests a minute for the public API (HTTP 429 above that). Batch up to 100 CVEs per call. Use the bulk CSV for anything over 1,000 CVEs.
- Terms: FIRST EPSS terms of use. Cite model version and score date from the response.
- Verified: `/data/v1/epss?cve=CVE-2024-3400` returned HTTP 200 on 16 October 2026.

### NIST National Vulnerability Database
- Endpoints: `GET` https://services.nvd.nist.gov/rest/json/cves/2.0; `GET` https://services.nvd.nist.gov/rest/json/cvehistory/2.0
- Auth: Optional API key in the `apiKey` request header.
- Rate limits: 5 requests per rolling 30 seconds without a key, 50 with a key. NVD asks clients to sleep about 6 seconds between requests. The limiter must enforce the rolling window, not a fixed one.
- Terms: Show the NVD notice: "This product uses data from the NVD API but is not endorsed or certified by the NVD."
- Verified: CVE API returned HTTP 200 without a key on 16 October 2026. Limits from NVD's developer start page.

### OSV.dev open source vulnerabilities
- Endpoints: `POST` https://api.osv.dev/v1/query; `POST` https://api.osv.dev/v1/querybatch; `GET` https://api.osv.dev/v1/vulns/<id>
- Auth: None.
- Rate limits: No key. Self-imposed 10 requests a second. Use querybatch for lists.
- Terms: OSV data is aggregated from many databases; keep each record's `database_specific` source and licence fields.
- Verified: `/v1/vulns/GHSA-jfh8-c2jp-5v3q` returned the Log4j record on 16 October 2026.

### Cloudflare Radar via Cloudflare's unified MCP server
- Endpoints: `MCP` https://mcp.cloudflare.com/mcp?codemode=false; `GET` https://api.cloudflare.com/client/v4/radar/annotations/outages; `GET` https://api.cloudflare.com/client/v4/radar/attacks/layer7/summary; `GET` https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events , /radar/bgp/leaks/events; `GET` https://api.cloudflare.com/client/v4/radar/ranking/top
- Auth: OAuth 2.1 through Hermes's MCP client (scope the grant to Radar read), or a custom API token with Account > Radar > Read sent as a bearer header.
- Rate limits: Cloudflare client API: 1,200 requests per 5 minutes per token; going over blocks calls for 5 minutes. Read `retry-after`.
- Terms: Cloudflare Radar API data is CC BY-NC 4.0: non-commercial use only unless you have an agreement with Cloudflare. Attribute Cloudflare Radar in every briefing that uses it.
- Verified: `https://mcp.cloudflare.com/mcp` answered 401 without auth on 16 October 2026 (exists). Hermes manifest read at the pinned commit. Radar REST endpoint returned the expected missing-auth error. Deprecation of the dedicated Radar server per its README, checked by a second inventory on the same date.

### AusCERT public security bulletins
- Endpoints: `GET` https://portal.auscert.org.au/rss/bulletins/
- Auth: None for the public RSS. Member-only portal content is out of scope.
- Rate limits: One request per 30 minutes.
- Terms: Return title, link, date and the feed summary only. Do not mirror full bulletins. Check AusCERT's terms before snapshotting.
- Verified: `portal.auscert.org.au/rss/bulletins/` returned `application/rss+xml` on 16 October 2026.

### abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker)
- Endpoints: `POST` https://urlhaus-api.abuse.ch/v1/url/ , /host/ , /payload/ ; GET /v1/urls/recent/; `POST` https://threatfox-api.abuse.ch/api/v1/; `POST` https://mb-api.abuse.ch/api/v1/; `GET` https://feodotracker.abuse.ch/downloads/ipblocklist.json
- Auth: `Auth-Key` HTTP header. Free key from https://auth.abuse.ch/. Mandatory since 30 June 2025.
- Rate limits: Fair use, no published number. Self-imposed 1 request a second per platform. Unauthenticated calls return 401.
- Terms: abuse.ch terms (effective 4 November 2025): free for not-for-profit use within query volume limits; commercial users may need a paid subscription through Spamhaus; no high-volume automated harvesting. Feodo Tracker separately states its datasets are CC0. The skill shows both statements and leaves the call to the operator.
- Verified: URLhaus and ThreatFox returned 401 without a key; Feodo JSON returned 200 on 16 October 2026. Auth rules from the abuse.ch 'Community First' notice and API pages.

### AlienVault OTX
- Endpoints: `GET` https://otx.alienvault.com/api/v1/indicators/<type>/<value>/<section>; `GET` https://otx.alienvault.com/api/v1/pulses/subscribed; `GET` https://otx.alienvault.com/api/v1/search/pulses?q=
- Auth: `X-OTX-API-KEY` header.
- Rate limits: Limits are not clearly published. Self-imposed 1 request a second, back off on 429.
- Terms: OTX terms of service. Pulses are community content and must be treated as untrusted text.
- Verified: `/api/v1/user/me` returned 'Authentication required' without a key on 16 October 2026.

### GreyNoise Community
- Endpoints: `GET` https://api.greynoise.io/v3/community/<ip>
- Auth: Optional `key` header with a community key.
- Rate limits: Community API has a daily quota (check current figure in GreyNoise docs). Self-imposed 1 request a second.
- Terms: GreyNoise community terms.
- Verified: `/v3/community/1.1.1.1` returned a valid JSON body without a key on 16 October 2026.

### Shodan InternetDB
- Endpoints: `GET` https://internetdb.shodan.io/<ip>
- Auth: None.
- Rate limits: Free, no key. Self-imposed 1 request a second.
- Terms: InternetDB is for non-commercial use per its page (verify wording before release).
- Verified: `/1.1.1.1` returned JSON on 16 October 2026.

### MITRE ATT&CK (STIX 2.1)
- Endpoints: `GET` https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json; `GET` https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
- Auth: None.
- Rate limits: Downloaded only when `index.json` reports a new version.
- Terms: ATT&CK terms of use require attribution to MITRE.
- Verified: `index.json` returned HTTP 200 on 16 October 2026.

### SigmaHQ detection rules
- Endpoints: `GET` https://api.github.com/repos/SigmaHQ/sigma/releases/latest
- Auth: None. Optional `GITHUB_TOKEN`.
- Rate limits: GitHub API limits. One download per release.
- Terms: Sigma rules are under the Detection Rule License (DRL) 1.1, which requires attribution. Keep `author` and `id` on every rule shown.
- Verified: SigmaHQ/sigma is public.

### crt.sh certificate transparency
- Endpoints: `GET` https://crt.sh/?q=<domain>&output=json
- Auth: None.
- Rate limits: Shared public service that is often slow. One request every 5 seconds, 90 second timeout.
- Terms: Public CT data.
- Verified: JSON query returned HTTP 200 on 16 October 2026.

### Australian reporting obligations (OAIC NDB, SOCI, ransomware payments)
- Endpoints: `GET` https://www.oaic.gov.au/privacy/notifiable-data-breaches/quick-reference-guide-for-responding-to-data-breaches; `GET` https://www.oaic.gov.au/privacy/notifiable-data-breaches/preventing-preparing-for-and-responding-to-data-breaches/data-breach-preparation-and-response/part-4-notifiable-data-breach-ndb-scheme; `GET` https://www.cyber.gov.au/report-a-cyber-security-incident; `GET` https://www.cisc.gov.au/resources-subsite/Documents/ncsi-guidance.pdf; `GET` https://www.legislation.gov.au/
- Auth: None.
- Rate limits: Fetched only by the regeneration workflow, once a week, 1 request every 5 seconds.
- Terms: Government content. Quote short passages with attribution. This is guidance, not legal advice, and every answer says so.
- Verified: OAIC guidance pages, cyber.gov.au reporting page, CISC guidance PDF and SOCI s 30BC on AustLII reviewed via search on 16 October 2026.

### Junction (Microsoft Graph, Defender, Sentinel)
- Endpoints: `MCP` Junction's own MCP server
- Auth: Microsoft Entra sign-in handled by Junction (see its README). No Microsoft secret lives in this repo.
- Rate limits: Microsoft Graph and ARM throttling, handled by Junction.
- Terms: Junction is MIT and not affiliated with Microsoft. Microsoft API terms apply.
- Verified: jusso-dev/junction is public; README describes CLI, MCP and local HTTP API.

### Brolga threat intel context engine
- Endpoints: `GET` http://127.0.0.1:8787/api/v1/health and /api/v1/stats (see Brolga docs/API.md for lookup routes)
- Auth: Bearer token.
- Rate limits: Local service. 20 requests a second.
- Terms: Brolga's own licence.
- Verified: jusso-dev/Brolga is public; README documents `brolga serve`, health and stats routes and `BROLGA_API_TOKEN`.

### ThreatSieve
- Endpoints: `CLI/HTTP` `pnpm --silent cli assess <indicator> --json` or the local API on 127.0.0.1:8787
- Auth: ThreatSieve scoped API key for the HTTP API.
- Rate limits: Deployment dependent. 5 requests a second default.
- Terms: ThreatSieve's own licence.
- Verified: jusso-dev/ThreatSieve is public; README documents the CLI `assess` command and local API.

### M365-Secure assessment reports
- Endpoints: `File` JSON report written by `m365-assess`
- Auth: None in this repo. The user runs M365-Secure themselves.
- Rate limits: Not applicable.
- Terms: M365-Secure's own licence.
- Verified: jusso-dev/M365-Secure is public; README documents HTML, CSV and JSON reports.

### VirusTotal via the official VirusTotal MCP server
- Endpoints: `MCP` https://github.com/VirusTotal/virustotal-mcp; `GET` https://www.virustotal.com/api/v3/files/{hash} , /urls/{id} , /domains/{domain} , /ip_addresses/{ip}
- Auth: `x-apikey` header with the user's own VirusTotal key.
- Rate limits: Public API: 4 requests a minute and 500 a day. Premium keys have their own quota.
- Terms: The VirusTotal Public API must not be used in commercial products or services, or in business workflows that do not contribute new files. Premium API is paid. Show this in the skill text and docs.
- Verified: `/api/v3/ip_addresses/8.8.8.8` returned 401 without a key from the build box on 16 October 2026. Repository `VirusTotal/virustotal-mcp` is public. Listed by a second inventory on 16 October 2026, which also read the Public API limits and terms.

### Have I Been Pwned via the official HIBP MCP server
- Endpoints: `MCP` https://haveibeenpwned.com/mcp; `GET` https://haveibeenpwned.com/api/v3/breaches; `GET` https://api.pwnedpasswords.com/range/{first 5 SHA-1 hex}; `GET` https://haveibeenpwned.com/api/v3/breachedaccount/{account}
- Auth: None for breach metadata and Pwned Passwords. Email and domain searches, pastes and stealer logs need a paid key or OAuth to an HIBP account with the right subscription.
- Rate limits: Depends on the key. A 429 carries `retry-after`; honour it.
- Terms: Breach data is CC BY 4.0 with attribution to Have I Been Pwned. No licence or attribution requirement on Pwned Passwords. Do not misrepresent the data source.
- Verified: `/api/v3/breaches` returned 200 and `https://haveibeenpwned.com/mcp` returned 406 to a plain GET (exists) from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026.

### GitHub Advisory Database via the GitHub MCP server
- Endpoints: `MCP` https://github.com/github/github-mcp-server; `GET` https://api.github.com/advisories
- Auth: Works unauthenticated at low volume. A fine-grained token with no repository access raises limits.
- Rate limits: GitHub REST limits: 60 requests an hour unauthenticated, 5,000 with a token.
- Terms: Advisory data is CC BY 4.0. Attribute the GitHub Advisory Database.
- Verified: `/advisories?per_page=1` returned 200 unauthenticated from the build box on 16 October 2026. `github/github-mcp-server` is public. Listed by a second inventory on 16 October 2026, which read the toolset names in the server README.

### Generic TAXII 2.1 reader for ASD CTIS and other TAXII sources
- Endpoints: `GET` <api root>/collections/; `GET` <api root>/collections/{id}/objects/?added_after=...
- Auth: HTTP Basic credentials issued to an ASD Network Partner during CTIS onboarding (membership-gated, under a confidentiality deed).
- Rate limits: Not published. Microsoft's onboarding guide for Sentinel suggests polling hourly for indicators at most a month old; use that as the ceiling.
- Terms: CTIS content is covered by the Network Partner deed. It must never appear in this public repository, fixtures, logs that are shared, or exports without a TLP check.
- Verified: cyber.gov.au partner pages could not be fetched by either inventory (site blocks automated clients); content seen through a search index and Microsoft's public `MSFT-AU-Security/SentinelCTIS` guide.

### NCSC NZ alerts (formerly CERT NZ)
- Endpoints: `GET` https://www.ncsc.govt.nz/alerts/?start=N
- Auth: None.
- Rate limits: One list page per hour, item pages at most 1 every 5 seconds.
- Terms: Licence not confirmed. Return title, date, link and extracted CVEs; quote short passages only.
- Verified: `/alerts/` returned 200 from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026, which found no RSS (several guessed feed paths returned 404).

### Cloudflare URL Scanner (unlisted scans, approval-gated)
- Endpoints: `POST` https://api.cloudflare.com/client/v4/accounts/{account_id}/urlscanner/v2/scan; `GET` https://api.cloudflare.com/client/v4/accounts/{account_id}/urlscanner/v2/result/{scan_id}
- Auth: Cloudflare API token with Account > URL Scanner > Edit.
- Rate limits: Cloudflare client API limits apply. Bulk submit up to 100 URLs; this connector submits one at a time.
- Terms: Scans default to Public on Cloudflare's side and appear in the recent scans list, so an internal URL could be published. This connector always sends Unlisted.
- Verified: Listed by a second inventory on 16 October 2026: docs, token permission, retention and visibility default read from Cloudflare's URL Scanner documentation.

### CVE Program records (CVE Services API and cvelistV5)
- Endpoints: `GET` https://cveawg.mitre.org/api/cve/{CVE-ID}; `GIT` https://github.com/CVEProject/cvelistV5
- Auth: None for reading.
- Rate limits: Not published. Self-imposed 1 request a second; bulk work uses the Git repository.
- Terms: Reproduction is allowed if copies keep MITRE's copyright designation and the licence. Keep the notice in `mcp/cve/SOURCE.md` and envelopes.
- Verified: `/api/cve/CVE-2021-44228` returned 200 from the build box on 16 October 2026. `CVEProject/cvelistV5` is public. Listed by a second inventory on 16 October 2026.

### AbuseIPDB IP reputation
- Endpoints: `GET` https://api.abuseipdb.com/api/v2/check; `GET` https://api.abuseipdb.com/api/v2/check-block
- Auth: `Key` header with a free or paid AbuseIPDB key.
- Rate limits: Free Individual plan: 1,000 checks a day and 100 block checks a day.
- Terms: Terms not confirmed by either inventory. Check before release.
- Verified: `/api/v2/check` returned 401 without a key from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026.

### Spamhaus DROP, DROPv6 and ASN-DROP
- Endpoints: `GET` https://www.spamhaus.org/drop/drop_v4.json; `GET` https://www.spamhaus.org/drop/drop_v6.json; `GET` https://www.spamhaus.org/drop/asndrop.json
- Auth: None.
- Rate limits: Update once a day and never auto-fetch more than once an hour.
- Terms: Provided free of charge; formal licence text not confirmed. Attribute Spamhaus.
- Verified: `drop_v4.json` returned 200 from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026.

### IRAP guidance
- Endpoints: `GET` https://www.cyber.gov.au/irap; `GET` https://www.cyber.gov.au/business-government/protecting-devices-systems/assessment-evaluation-programs/irap/irap-consumer-guide
- Auth: None.
- Rate limits: Fetched only by the regeneration workflow, weekly, 1 request every 5 seconds.
- Terms: Government content. Quote short passages with attribution.
- Verified: Neither inventory could fetch cyber.gov.au directly on 16 October 2026; pages were seen through a search index and an earlier snapshot.

### Protective Security Policy Framework (PSPF)
- Endpoints: `GET` https://www.protectivesecurity.gov.au/publications-library/pspf-page-2026; `GET` https://www.protectivesecurity.gov.au/
- Auth: None.
- Rate limits: Regeneration workflow only, weekly.
- Terms: Licence not confirmed. Quote short passages with attribution.
- Verified: Could not fetch on 16 October 2026 (dropped connection, HTTP 500 to a fetch service); paths from an earlier snapshot.

### Scamwatch alerts
- Endpoints: `GET` https://www.scamwatch.gov.au/
- Auth: None.
- Rate limits: One request per 6 hours.
- Terms: Licence not confirmed.
- Verified: Listed by a second inventory on 16 October 2026: a fetch service returned the page, curl got 403.

### data.gov.au (CKAN)
- Endpoints: `GET` https://data.gov.au/data/api/3/action/package_search; `GET` https://data.gov.au/data/api/3/action/package_show
- Auth: None.
- Rate limits: One request a second.
- Terms: Per dataset, in each record's `license_id`. Datasets with no licence are flagged.
- Verified: `status_show` returned 200 from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026.

### AusCERT member URL feed (AusMISP goes through the MISP connector)
- Endpoints: `GET` (member URL feed, format to confirm with a member); `MISP` AusMISP
- Auth: Paid AusCERT membership.
- Rate limits: Per member terms; default hourly.
- Terms: Member terms. Member data never enters this repository or fixtures.
- Verified: Listed by a second inventory on 16 October 2026: membership and service pages read; feed format not public.

### ASD Blueprint for Secure Cloud
- Endpoints: `GET` https://blueprint.asd.gov.au/<page>
- Auth: None.
- Rate limits: Regeneration workflow only, weekly, 1 request every 5 seconds.
- Terms: Licence not confirmed.
- Verified: Homepage returned 200 from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026.

### PhishTank verified phishing URLs
- Endpoints: `GET` https://data.phishtank.com/data/<app key>/online-valid.json
- Auth: Free application key for automated downloads; a descriptive `User-Agent` is required.
- Rate limits: Hourly at most.
- Terms: Licence not confirmed.
- Verified: Developer page returned 200 from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026.

### OpenPhish community feed
- Endpoints: `GET` https://openphish.com/feed.txt
- Auth: None.
- Rate limits: Hourly at most.
- Terms: Licence not confirmed. The community feed is a small sample.
- Verified: `feed.txt` returned a 302 from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026, which read 200 with a short feed.

### MISP via the official MISP MCP server, for your own instance or AusMISP
- Endpoints: `MCP` https://github.com/MISP/misp-mcp; `REST` <your MISP instance>
- Auth: The instance's API key, ideally a read-only key.
- Rate limits: Per instance.
- Terms: MISP software is AGPL-3.0; feed terms vary per feed. Respect TLP and sharing groups.
- Verified: `MISP/misp-mcp` is public. Listed by a second inventory on 16 October 2026.

### OpenCTI (your own instance)
- Endpoints: `GRAPHQL` <your OpenCTI instance>/graphql; `MCP` https://github.com/FiligranHQ/xtm-mcp
- Auth: The instance's API token.
- Rate limits: Per instance.
- Terms: Community Edition Apache-2.0; Enterprise Edition has its own licence.
- Verified: `FiligranHQ/xtm-mcp` is public. Listed by a second inventory on 16 October 2026.

### Hudson Rock Cavalier (infostealer exposure by domain)
- Endpoints: `POST` https://api.hudsonrock.com/json/v3/search-by-domain; `POST` https://api.hudsonrock.com/json/v3/search-by-domain/overview; `POST` https://api.hudsonrock.com/json/v3/search-by-domain/assessment
- Auth: `api-key` header with the user's Cavalier key. The key is limited to the domains on the customer's whitelist; other domains need pre-approved `external_domains`.
- Rate limits: Documented for the assessment endpoint: 50 requests per 10 seconds, up to 2,500 URLs per type, 90 second maximum response time. Treat it as the ceiling for all endpoints.
- Terms: Commercial licence. Default flags: no on-disk cache of records, store counts and metadata only, no STIX export, no sharing outside the profile. Relax only if the user's contract allows it.
- Verified: Vendor docs (docs.hudsonrock.com): authentication page names the `api-key` header; Domain Intelligence pages list the endpoints, parameters and the rate limit above. `search-by-domain` returned 401 to a bad key from the build box on 16 October 2026.

### SpyCloud Enterprise Protection (breach and malware exposure on a watchlist)
- Endpoints: `GET` https://api.spycloud.io/enterprise-v2/watchlist; `GET` https://api.spycloud.io/enterprise-v2/breach/catalog/{id}
- Auth: `X-API-KEY` header with the user's key from the SpyCloud customer portal.
- Rate limits: 429 is documented; no number published in the public docs. Read the response headers and back off.
- Terms: Commercial licence. Default flags: no on-disk cache of records, metadata only in the store, no STIX export. SpyCloud can return hashed values if hashing is enabled on the key; prefer that.
- Verified: Vendor docs (docs.spycloud.com): API guidelines name the `X-API-KEY` header; reference pages document the watchlist and breach catalogue endpoints and parameters above.

### UpGuard CyberRisk (identity breaches, data leaks and typosquats; Australian vendor)
- Endpoints: `GET` https://cyber-risk.upguard.com/api/public/breaches; `GET` https://cyber-risk.upguard.com/api/public/breach?id=...; `GET` https://cyber-risk.upguard.com/api/public/dataleaks/disclosures; `GET` https://cyber-risk.upguard.com/api/public/typosquat , /typosquat/details?domain=
- Auth: `Authorization` header set to the API key itself (no `Bearer` prefix). Each key carries the permissions chosen when it was created.
- Rate limits: 429 is documented; no number published. Back off on 429.
- Terms: Commercial licence. Default flags: metadata in the store, no STIX export. Typosquat domains are the user's own monitoring results and may be exported if the user allows it.
- Verified: Vendor docs (cyber-risk.upguard.com/api/docs, API version 1.12 on the page): base URL, `Authorization` header and the permissions per endpoint. `/api/public/breaches` returned 403 to a bad key from the build box on 16 October 2026.

### ransomware.live victim tracker (free, filter by country AU)
- Endpoints: `GET` https://api-pro.ransomware.live/victims/?country=AU; `GET` https://api-pro.ransomware.live/victims/recent; `GET` https://api-pro.ransomware.live/victims/search; `GET` https://api-pro.ransomware.live/csirt/AU; `GET` https://api.ransomware.live/v2/recentvictims
- Auth: Free. The PRO API needs a free key in the `X-API-KEY` header (from ransomware.live/my). The v2 API needs no key.
- Rate limits: PRO API: 500,000 requests a month per key, 429 beyond. v2: rate limited, no number published. Self-imposed: one poll an hour.
- Terms: Free community project. Victim entries are claims scraped from criminal leak sites, not confirmed incidents. Check the site's terms before redistributing; default flags: store metadata, no STIX export of victim names.
- Verified: PRO API OpenAPI spec (api-pro.ransomware.live/swagger.json): `X-API-KEY`, 500,000 requests a month, `country` filter. v2 `/info` and `/recentvictims` returned 200 without a key on 16 October 2026.

### Recorded Future (identity exposures and playbook alerts)
- Endpoints: `POST` https://api.recordedfuture.com/identity/credentials/search; `POST` https://api.recordedfuture.com/playbook-alert/search; `GET` https://api.recordedfuture.com/playbook-alert/identity_novel_exposures/{id}
- Auth: `X-RFToken` header. Tokens are created by an Enterprise Administrator; entitlements follow the licensed modules.
- Rate limits: Not published in the overview. Back off on 429.
- Terms: Commercial licence. Default flags: metadata only, no STIX export.
- Verified: Vendor docs (docs.recordedfuture.com): authentication table (`X-RFToken`, base URL) and the identity search and playbook alert reference pages. A bad token got 401 from the build box on 16 October 2026.

### Flashpoint Ignite (compromised credentials and indicators)
- Endpoints: `GET` https://api.flashpoint.io/technical-intelligence/v2/indicators; `GET` (credential sightings search path: confirm in docs.flashpoint.io)
- Auth: Bearer token (Ignite API key).
- Rate limits: Not published publicly. Back off on 429.
- Terms: Commercial licence. Default flags: metadata only, no STIX export.
- Verified: `technical-intelligence/v2/indicators` returned 401 without a token from the build box on 16 October 2026. Query syntax and bearer auth from vendor-published integrations (Cortex XSOAR, Splunk SOAR); the portal itself was not readable.

### Intel 471 Titan (watchers, alerts, credentials and breach alerts)
- Endpoints: `GET` https://api.intel471.com/v1/alerts; `GET` https://api.intel471.com/v1/watcherGroups , /watcherGroups/{uid}/watchers; `GET` https://api.intel471.com/v1/credentials , /credentials/occurrences , /credentialSets; `GET` https://api.intel471.com/v1/breachAlerts
- Auth: HTTP Basic: the registered Intel 471 email as the username and the API key as the password.
- Rate limits: Not published in the client README. Back off on 429.
- Terms: Commercial licence. Default flags: metadata only, no STIX export.
- Verified: Vendor's public OpenAPI-generated client (intel471/titan-client-python) lists the endpoints above and Basic auth. `api.intel471.com/v1/` returned 401 from the build box on 16 October 2026.

### Google Threat Intelligence Digital Threat Monitoring (formerly Mandiant)
- Endpoints: `GET` https://www.virustotal.com/api/v3/dtm/alerts; `GET` https://www.virustotal.com/api/v3/dtm/monitors
- Auth: `x-apikey` header with a Google Threat Intelligence key, plus an `x-tool` header naming the integration (for example `hermes-cyber-au.v0.x`).
- Rate limits: Per licence. Back off on 429.
- Terms: Commercial licence. Default flags: metadata only, no STIX export.
- Verified: Vendor docs (gtidocs.virustotal.com): DTM pagination page, the Mandiant migration guide and the DTM OpenAPI reference. `x-tool` from the vendor's public `VirusTotal/gti-dev-kit`.

### CrowdStrike Falcon Adversary Intelligence Recon (dark web monitoring notifications)
- Endpoints: `POST` https://api.crowdstrike.com/oauth2/token; `GET` Recon notifications query and entities endpoints (FalconPy `query_notifications`, `get_notifications`); `GET` Recon rules query and entities endpoints (FalconPy `query_rules`, `get_rules`)
- Auth: OAuth2 client credentials from an API client created in Falcon with read scope for Recon monitoring rules only.
- Rate limits: Per Falcon API limits, returned in headers. Back off on 429.
- Terms: Commercial licence. Default flags: metadata only, no STIX export.
- Verified: Vendor developer centre Recon collection page and FalconPy `recon.py`. The token endpoint returned 401 from the build box on 16 October 2026.

### SOCRadar (company incidents: dark web, leaks, brand and attack surface)
- Endpoints: `GET` https://platform.socradar.com/api/company/{company_id}/incidents/v4
- Auth: Company API key in the `Api-Key` header, plus the numeric company id.
- Rate limits: Not published publicly. Back off on 429.
- Terms: Commercial licence. Default flags: metadata only, no STIX export.
- Verified: Vendor API page (socradar.io/socradar-apis) and vendor-published integrations (Elastic, Cortex XSOAR) for the incidents v4 path and `Api-Key` header. Confirm parameters in the customer portal at build time.

### DarkOwl Vision (dark web search)
- Endpoints: `GET` https://api.darkowl.com/api/v1/search?q=...
- Auth: HMAC-SHA1 request signing: sign method, path and a UTC `Date` header with the private key and send `Authorization: OWL <public key>:<base64 signature>`.
- Rate limits: Per licence. Back off on 429.
- Terms: Commercial licence. Default flags: no snippets stored, counts and links only, no STIX export.
- Verified: Vendor support knowledge base: search API documentation and the authorisation header calculation page. `api.darkowl.com` answered 403 to an unsigned request from the build box on 16 October 2026.
