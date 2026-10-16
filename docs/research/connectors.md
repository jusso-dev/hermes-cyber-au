# Connector inventory

Checked on 16 October 2026. This list was compiled and verified independently for this plan. Each connector ticket carries endpoints, auth, limits, terms and what was verified.

| Connector | Server | Group | Auth | Milestone | Docs |
|---|---|---|---|---|---|
| ASD's ACSC alerts, advisories and publications | `asd` | Australian government | none | v0.1 MVP | https://www.cyber.gov.au/ |
| Information Security Manual (ISM) OSCAL catalogue | `ism` | Australian government | `GITHUB_TOKEN` (optional) | v0.1 MVP | https://github.com/AustralianCyberSecurityCentre/ism-oscal |
| Essential Eight and ASD Essentials | `e8` | Australian government | none | v0.1 MVP | https://www.cyber.gov.au/publication/what-is-the-essentials |
| CISA Known Exploited Vulnerabilities | `kev` | Vulnerability intelligence | none | v0.1 MVP | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| FIRST EPSS | `epss` | Vulnerability intelligence | none | v0.1 MVP | https://api.first.org/epss/ |
| NIST National Vulnerability Database | `nvd` | Vulnerability intelligence | `NVD_API_KEY` (optional) | v0.1 MVP | https://nvd.nist.gov/developers/vulnerabilities |
| OSV.dev open source vulnerabilities | `osv` | Vulnerability intelligence | none | v0.2 | https://google.github.io/osv.dev/api/ |
| Cloudflare Radar via Cloudflare's unified MCP server | `cloudflare_radar` | Internet and attack telemetry | `CLOUDFLARE_RADAR_API_TOKEN` (optional) | v0.1 MVP | https://developers.cloudflare.com/radar/ |
| AusCERT public security bulletins | `auscert` | Australian community | none | v0.1 MVP | https://www.auscert.org.au/ |
| abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker) | `abusech` | Global threat intelligence | `ABUSECH_AUTH_KEY` | v0.1 MVP | https://abuse.ch/ |
| AlienVault OTX | `otx` | Global threat intelligence | `OTX_API_KEY` | v0.2 | https://otx.alienvault.com/api |
| GreyNoise Community | `greynoise` | Global threat intelligence | `GREYNOISE_API_KEY` (optional) | v0.2 | https://docs.greynoise.io/ |
| Shodan InternetDB | `internetdb` | Global threat intelligence | none | v0.2 | https://internetdb.shodan.io/ |
| MITRE ATT&CK (STIX 2.1) | `attack` | Frameworks | none | v0.1 MVP | https://github.com/mitre-attack/attack-stix-data |
| SigmaHQ detection rules | `sigma` | Frameworks | `GITHUB_TOKEN` (optional) | v0.2 | https://github.com/SigmaHQ/sigma |
| crt.sh certificate transparency | `crtsh` | Global threat intelligence | none | v0.2 | https://crt.sh/ |
| Australian reporting obligations (OAIC NDB, SOCI, ransomware payments) | `aureg` | Australian government | none | v0.2 | https://www.oaic.gov.au/privacy/notifiable-data-breaches |
| Junction (Microsoft Graph, Defender, Sentinel) | `junction` | Author's public tools | `JUNCTION_BIN` (optional) | v0.2 | https://github.com/jusso-dev/junction |
| Brolga threat intel context engine | `brolga` | Author's public tools | `BROLGA_URL` (optional), `BROLGA_API_TOKEN` | v1.0 | https://github.com/jusso-dev/Brolga |
| ThreatSieve | `threatsieve` | Author's public tools | `THREATSIEVE_URL` (optional), `THREATSIEVE_API_KEY` (optional) | v1.0 | https://github.com/jusso-dev/ThreatSieve |
| M365-Secure assessment reports | `(none)` | Author's public tools | none | v0.2 | https://github.com/jusso-dev/M365-Secure |

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
