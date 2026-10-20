# Data sources

Generated from `feeds/catalogue.yaml`. Terms below are recorded source claims, not legal advice.
Sources with unconfirmed or non-commercial terms stay off until the operator verifies permission.

## CISA Known Exploited Vulnerabilities (cisa-kev)

Connector: `cisa-kev`. Default: on.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Terms: CC0 1.0. Do not use the CISA logo or DHS seal.

## FIRST EPSS (first-epss)

Connector: `first-epss`. Default: on.

Source: https://api.first.org/data/v1/epss

Terms: Free to use, attribution requested (EPSS FAQ). No named licence.

## ASD ACSC alerts, advisories, publications, threats and news (asd-acsc)

Connector: `asd-acsc`. Default: on.

Source: https://www.cyber.gov.au/rss/alerts

Terms: CC BY 4.0 with exclusions (cyber.gov.au copyright page). Not endorsed by ASD.

Rate limit is one feed poll per 10 minutes. Item pages are cached for 7 days.

## Information Security Manual (ISM) OSCAL (asd-ism)

Connector: `asd-ism`. Default: on.

Source: https://api.github.com/repos/AustralianCyberSecurityCentre/ism-oscal/releases

Terms: CC BY 4.0 (ism-oscal README), Commonwealth of Australia. Not endorsed by ASD.

The release list is cached for 12 hours, raw release files for 7 days. GITHUB_TOKEN only raises the GitHub API limit.

## Essential Eight and ASD Essentials (asd-essentials)

Connector: `asd-essentials`. Default: off.

Source: https://www.cyber.gov.au/publication/essentials-for-enterprise-it

Terms: Not confirmed in SOURCE.md. Published by ASD. Record the ISM release tag and page SHA-256.

Tools answer from the shipped snapshot unless a live health check is asked for.

## ASD Blueprint for Secure Cloud (asd-blueprint)

Connector: `asd-blueprint`. Default: off.

Source: https://blueprint.asd.gov.au/

Terms: Not confirmed. Published by ASD. Not endorsed by ASD.

Search reads the shipped snapshot. A refresh is meant to run weekly.

## AU regulatory guidance (OAIC NDB, ACSC reporting, CISC, Federal Register of Legislation) (au-regulatory)

Connector: `au-regulatory`. Default: on.

Source: https://www.oaic.gov.au/privacy/notifiable-data-breaches/quick-reference-guide-for-responding-to-data-breaches

Terms: Commonwealth legislation and government guidance. No licence name recorded in SOURCE.md. Short quotes only, with source URL.

Fetches run from the regeneration path about once a week. The CISC guidance is a PDF. Tool calls answer from the shipped snapshot.

## AusCERT security bulletins (auscert)

Connector: `auscert`. Default: off.

Source: https://portal.auscert.org.au/rss/bulletins/

Terms: Not confirmed. Return title, link, date and summary only. Do not mirror full bulletins.

## IRAP consumer guide and programme pages (irap)

Connector: `irap`. Default: on.

Source: https://www.cyber.gov.au/irap

Terms: CC BY 4.0 except the Coat of Arms (July 2025 consumer guide). Not endorsed by ASD.

## Protective Security Policy Framework (pspf)

Connector: `pspf`. Default: off.

Source: https://www.protectivesecurity.gov.au/publications-library/pspf-page-2026

Terms: Not confirmed. Quote short passages with attribution.

## Scamwatch alerts (scamwatch)

Connector: `scamwatch`. Default: off.

Source: https://www.scamwatch.gov.au/

Terms: Not confirmed. Quote short passages with attribution.

## data.gov.au dataset search (datagov-au)

Connector: `datagov-au`. Default: on.

Source: https://data.gov.au/data/api/3/action/package_search

Terms: Per dataset (license_id). Datasets with no licence are flagged.

## NCSC New Zealand alerts (ncsc-nz)

Connector: `ncsc-nz`. Default: off.

Source: https://www.ncsc.govt.nz/alerts/

Terms: Not confirmed. Quote short passages only.

New Zealand source. The region enum has no NZ value. Alert pages are cached for 7 days.

## NIST National Vulnerability Database (nvd)

Connector: `nvd`. Default: on.

Source: https://services.nvd.nist.gov/rest/json/cves/2.0

Terms: Public domain (17 USC). NVD API terms of use notice required.

Search is cached for 1 hour, CVE and history lookups for 1 day. The connector works without a key, but servers.yaml lists NVD_API_KEY in required_env, so render_config disables the server when it is unset.

## CVE Program records (cve-program)

Connector: `cve-program`. Default: on.

Source: https://cveawg.mitre.org/api/cve

Terms: CVE Terms of Use. Keep MITRE's copyright designation.

## OSV vulnerability database (osv)

Connector: `osv`. Default: on.

Source: https://api.osv.dev/v1

Terms: Per record. Each record's database_specific source and licence fields are kept.

Queries are cached for 6 hours, records for 1 day.

## MITRE ATT&CK STIX data (mitre-attack)

Connector: `mitre-attack`. Default: on.

Source: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json

Terms: ATT&CK terms of use. Attribution to MITRE required. Not endorsed by MITRE.

index.json is cached for 1 hour. A bundle is downloaded only when the index reports a new version.

## SigmaHQ detection rules (sigma)

Connector: `sigma`. Default: on.

Source: https://api.github.com/repos/SigmaHQ/sigma/releases/latest

Terms: Detection Rule License (DRL) 1.1. Keep the rule id and author.

The release document is cached for 12 hours and each rule package is downloaded once per release tag from GitHub release asset hosts. SOURCE.md lists release-assets.githubusercontent.com as an egress host but mcp/egress-allowlist.yaml does not.

## crt.sh certificate transparency search (crtsh)

Connector: `crtsh`. Default: off.

Source: https://crt.sh/

Terms: Not confirmed. Public certificate transparency data from crt.sh.

## Shodan InternetDB (shodan-internetdb)

Connector: `shodan-internetdb`. Default: off.

Source: https://internetdb.shodan.io

Terms: Free for non-commercial use. Commercial use needs a Shodan enterprise licence.

## Spamhaus DROP and ASN-DROP (spamhaus-drop)

Connector: `spamhaus-drop`. Default: off.

Source: https://www.spamhaus.org/drop/drop_v4.json

Terms: Provided free of charge. Formal licence text not confirmed. Attribute Spamhaus.

## OpenPhish community feed (openphish)

Connector: `openphish`. Default: off.

Source: https://openphish.com/feed.txt

Terms: Not confirmed. The community feed is a small sample.

## abuse.ch Feodo Tracker botnet C2 blocklist (feodo-tracker)

Connector: `abusech`. Default: off.

Source: https://feodotracker.abuse.ch/downloads/ipblocklist.json

Terms: CC0 (Feodo Tracker statement). The abuse.ch terms also apply.

Served by the abusech server, which is off by default and needs ABUSECH_AUTH_KEY for its other tools. cyberau-mcp refresh fetches this blocklist without a key.

## abuse.ch URLhaus, ThreatFox and MalwareBazaar (abusech)

Connector: `abusech`. Default: off.

Source: https://urlhaus-api.abuse.ch/v1/url/

Terms: abuse.ch terms (4 November 2025). Free for not-for-profit use. Commercial use may need a Spamhaus subscription.

Lookups are cached for 1 hour, recent lists for 15 minutes. Off by default for licence terms.

## AbuseIPDB (abuseipdb)

Connector: `abuseipdb`. Default: off.

Source: https://api.abuseipdb.com/api/v2/check

Terms: Not confirmed. Attribute AbuseIPDB.

## AlienVault OTX (otx)

Connector: `otx`. Default: on.

Source: https://otx.alienvault.com/api/v1

Terms: OTX terms of service. Pulses are untrusted community content.

Pulses are cached for 1 hour, indicators for 6 hours.

## GreyNoise Community API (greynoise)

Connector: `greynoise`. Default: on.

Source: https://api.greynoise.io/v3/community

Terms: GreyNoise terms of service. Cite GreyNoise.

## ransomware.live victim claims (ransomware-live)

Connector: `ransomware-live`. Default: off.

Source: https://api.ransomware.live/v2/recentvictims

Terms: Not confirmed. Free community project. Check the site's terms before redistributing.

The key selects the PRO API. Victim entries are claims from leak sites, not confirmed incidents.

## PhishTank online-valid database (phishtank)

Connector: `phishtank`. Default: off.

Source: https://data.phishtank.com/data/online-valid.json

Terms: Not confirmed. Cite PhishTank.

The connector has a package and SOURCE.md but no entry in mcp/servers.yaml, so it is not launched as a server. The optional key is a path segment. PHISHTANK_APP_KEY is not in .env.template.

## Have I Been Pwned (official MCP server) (hibp)

Connector: `hibp`. Default: on.

Source: https://haveibeenpwned.com/mcp

Terms: Breach data CC BY 4.0, attribute Have I Been Pwned. Pwned Passwords has no attribution requirement.

Breach metadata and the Pwned Passwords range need no key. Account and domain lookups need HIBP_API_KEY and a person's approval. Public tools are cached for 1 day. HIBP_API_KEY is not in .env.template.

## GitHub Advisory Database (github-mcp-server) (github-advisories)

Connector: `github-advisories`. Default: off.

Source: https://api.github.com/advisories

Terms: CC BY 4.0. Attribute the GitHub Advisory Database.

The wrapped server receives the token as GITHUB_PERSONAL_ACCESS_TOKEN. It answers with a sign-in link without one. GITHUB_ADVISORY_TOKEN is not in .env.template.

## Custom RSS and Atom feeds (watch packs) (custom-feeds)

Connector: `custom-feeds`. Default: on.

Source: https://api.msrc.microsoft.com/update-guide/rss

Terms: Each feed's publisher terms. The shipped microsoft-security pack is Microsoft content under the Microsoft Terms of Use.

Generic reader for the feeds turned on in watchlists.yaml. Nothing is fetched until a pack or feed is listed there. URLs are the shipped microsoft-security pack.

## Cloudflare Radar API (cloudflare-radar)

Connector: `cloudflare-radar`. Default: off.

Source: https://api.cloudflare.com/client/v4/radar

Terms: CC BY-NC 4.0. Non-commercial use only unless you have an agreement with Cloudflare.

Custom API token with only Account > Radar > Read, sent as a bearer token. Six read-only tools.

## Cloudflare URL Scanner (cloudflare-urlscanner)

Connector: `cloudflare-urlscanner`. Default: off.

Source: https://api.cloudflare.com/client/v4/accounts

Terms: Not confirmed in SOURCE.md. Scans are always sent Unlisted. Submitting needs a person's approval.

Calls {url}/<account id>/urlscanner/v2/scan and /result. Submissions are cached for 1 day, results for 1 year. CLOUDFLARE_URLSCAN_API_TOKEN and CLOUDFLARE_ACCOUNT_ID are not in .env.template.

## VirusTotal (official virustotal-mcp, VTAI) (virustotal)

Connector: `virustotal`. Default: off.

Source: https://ai.virustotal.com/api/v3

Terms: VirusTotal Public API must not be used commercially. Premium API is paid.

servers.yaml has no connector key for this wrapped server. Reports are cached for 24 hours. VTAI_TOKEN is not in .env.template.

## ThreatSieve assessment API (threatsieve)

Connector: `threatsieve`. Default: off.

Source: ${THREATSIEVE_URL}

Terms: ThreatSieve's own licence.

Calls POST /v1/assess. THREATSIEVE_URL defaults to http://127.0.0.1:8787 when unset.

## Hindsight memory server (operator supplied) (hindsight)

Connector: `hindsight`. Default: off.

Source: ${HINDSIGHT_BASE_URL}

Terms: Operator's own server. Use only a server you operate or are allowed to use.

No host is shipped. HINDSIGHT_BASE_URL must be https.

## MISP instance (misp-mcp) (misp)

Connector: `misp`. Default: off.

Source: ${MISP_URL}

Terms: Per feed in your instance. MISP software is AGPL-3.0. Respect TLP and sharing groups.

MISP_URL and MISP_API_KEY are not in .env.template.

## OpenCTI instance (opencti)

Connector: `opencti`. Default: off.

Source: ${OPENCTI_URL}

Terms: Per source in your instance. OpenCTI Community Edition is Apache-2.0.

GraphQL at <OPENCTI_URL>/graphql.

## TAXII 2.1 server (for example ASD CTIS) (taxii-ctis)

Connector: `taxii-ctis`. Default: off.

Source: ${TAXII_API_ROOT}

Terms: ASD Network Partner deed for CTIS content. TLP check before any copy or export.

Collection lists are cached for 1 day. No host is shipped in the egress allowlist.

## Hudson Rock Cavalier (hudson-rock)

Connector: `hudson-rock`. Default: off.

Source: https://api.hudsonrock.com/json/v3/search-by-domain

Terms: Commercial licence. Session cache only. Store counts and metadata only.

## SpyCloud Enterprise (spycloud)

Connector: `spycloud`. Default: off.

Source: https://api.spycloud.io/enterprise-v2/breach/data/watchlist

Terms: Commercial licence. Store metadata only. No STIX export.

Records are cached for 1 hour, breach catalogue metadata for 1 day.

## UpGuard BreachSight (upguard)

Connector: `upguard`. Default: off.

Source: https://cyber-risk.upguard.com/api/public

Terms: Commercial licence. Store metadata only. No STIX export.

Session cache 15 minutes. Typosquat lists are cached for up to 12 hours.

## Recorded Future API (recorded-future)

Connector: `recorded-future`. Default: off.

Source: https://api.recordedfuture.com

Terms: Commercial licence. Identity and alert metadata only. No STIX export.

Playbook alerts are cached for 1 hour, identity results for 12 hours.

## Recorded Future official MCP server (recorded-future-mcp)

Connector: `recorded-future`. Default: off.

Source: https://mcp.recordedfuture.com/mcp

Terms: Commercial licence. Needs a subscription with unlimited integrations.

One MCP tool call counts as one API call against the shared daily limit.

## Flashpoint Ignite technical indicators (flashpoint)

Connector: `flashpoint`. Default: off.

Source: https://api.flashpoint.io/technical-intelligence/v2/indicators

Terms: Commercial licence. Redistribution forbidden.

## Intel 471 Titan (intel471)

Connector: `intel471`. Default: off.

Source: https://api.intel471.com/v1

Terms: Commercial licence. Store metadata only. No STIX export.

## Google Threat Intelligence Digital Threat Monitoring (google-ti-dtm)

Connector: `google-ti-dtm`. Default: off.

Source: https://www.virustotal.com/api/v3/dtm/alerts

Terms: Commercial licence. Redistribution forbidden.

## CrowdStrike Falcon Intelligence Recon (crowdstrike-recon)

Connector: `crowdstrike-recon`. Default: off.

Source: https://api.crowdstrike.com

Terms: Commercial licence. Store metadata only. No STIX export.

OAuth2 client credentials. FALCON_BASE_URL is optional.

## SOCRadar incidents (socradar)

Connector: `socradar`. Default: off.

Source: https://platform.socradar.com/api/company/{company_id}/incidents/v4

Terms: Commercial licence. Store metadata only. No STIX export.

## DarkOwl Vision search (darkowl)

Connector: `darkowl`. Default: off.

Source: https://api.darkowl.com/api/v1/search

Terms: Commercial licence. Store counts and links only, no snippets.

## Flare Firework API (flare)

Connector: `flare`. Default: off.

Source: https://api.flare.io

Terms: Commercial licence. Store event metadata only. No STIX export.

The key is exchanged for a 1 hour bearer token. Events are cached for 5 minutes, identifiers for 1 hour.

## Flare official MCP server (flare-mcp)

Connector: `flare-mcp`. Default: off.

Source: https://api.flare.io/mcp

Terms: Commercial licence (same terms as the flare connector).

No connector package or egress entry named flare-mcp. The host is covered by the flare allowlist entry.
