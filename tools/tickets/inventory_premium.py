"""Premium and commercial intel feeds, plus one free ransomware victim tracker.
Checked on 16 October 2026 against vendor documentation. Paths that came from vendor-published
integrations rather than the vendor's own docs say so in `verified`."""
from __future__ import annotations

from common import M_V02, M_V10
from inventory import obj, S, DATE, LIMIT

DOMAIN = {"type": S, "format": "hostname"}
DOMAINS = {"type": "array", "items": DOMAIN, "minItems": 1, "maxItems": 50,
           "description": "Must all be on the user's org-exposure watchlist unless `allow_external` is set by the user"}
SINCE = {"type": S, "format": "date", "description": "YYYY-MM-DD, Australia/Sydney"}

# terms: (cache, store, stix, note). cache: none | session | ttl. Values are the conservative defaults
# until the user's own contract says otherwise; the user can relax them in config.yaml, never the code.
PREMIUM = [
    dict(
        key="hudson-rock", server="hudsonrock", name="Hudson Rock Cavalier (infostealer exposure by domain)",
        group="Credential and infostealer exposure", milestone=M_V10, priority="p3", paid=True,
        docs="https://docs.hudsonrock.com/",
        endpoints=[
            ("POST", "https://api.hudsonrock.com/json/v3/search-by-domain", "Infostealer records for 1 to 50 domains; filters `types` (employees, users, third_parties), `keywords`, dates, `cursor`"),
            ("POST", "https://api.hudsonrock.com/json/v3/search-by-domain/overview", "Statistical overview per domain"),
            ("POST", "https://api.hudsonrock.com/json/v3/search-by-domain/assessment", "Third party risk assessment for one domain"),
        ],
        auth="`api-key` header with the user's Cavalier key. The key is limited to the domains on the customer's whitelist; other domains need pre-approved `external_domains`.",
        env=[("HUDSONROCK_API_KEY", True, "Cavalier API key (paid). Bring your own licence.")],
        rate="Documented for the assessment endpoint: 50 requests per 10 seconds, up to 2,500 URLs per type, 90 second maximum response time. Treat it as the ceiling for all endpoints.",
        cache="Default `session` only (in memory, cleared at session end). Counts and first-seen dates go to the exposures table; credential values never do.",
        terms="Commercial licence. Default flags: no on-disk cache of records, store counts and metadata only, no STIX export, no sharing outside the profile. Relax only if the user's contract allows it.",
        terms_flags=("session", "metadata", False),
        hosts=["api.hudsonrock.com"],
        notes="Infostealer data is the most direct signal that an Australian organisation's staff or customers are exposed, and the domain search maps cleanly onto the org-exposure watchlist. Hudson Rock also publishes a free preview key for its older Cavalier v2 base (`cavalier.hudsonrock.com/api/json/v2`); do not ship or use that key in tests.",
        verified="Vendor docs (docs.hudsonrock.com): authentication page names the `api-key` header; Domain Intelligence pages list the endpoints, parameters and the rate limit above. `search-by-domain` returned 401 to a bad key from the build box on 16 October 2026.",
        tools=[
            ("hudsonrock_domain_exposure", "Counts of compromised employees, users and third parties for watchlist domains, with first and last compromise dates. Never returns passwords or cookies.", obj({"domains": DOMAINS, "types": {"type": "array", "items": {"enum": ["employees", "users", "third_parties"]}}, "since": SINCE}, ["domains"])),
            ("hudsonrock_domain_overview", "Vendor overview statistics for one watchlist domain.", obj({"domain": DOMAIN}, ["domain"])),
        ],
        fixtures=["search_by_domain_synthetic.json (synthetic: example.com.au, fake hosts, no credentials)", "overview_synthetic.json (synthetic)", "hudsonrock_401.json", "hudsonrock_429.json", "hudsonrock_408_timeout.json"],
    ),
    dict(
        key="spycloud", server="spycloud", name="SpyCloud Enterprise Protection (breach and malware exposure on a watchlist)",
        group="Credential and infostealer exposure", milestone=M_V10, priority="p3", paid=True,
        docs="https://docs.spycloud.com/public-sc/docs/api-guidelines",
        endpoints=[
            ("GET", "https://api.spycloud.io/enterprise-v2/watchlist", "Records matching the customer's watchlist; filters `since`, `until`, `type` (corporate, infected, email_domain, target_domain), `watchlist_type` (email, domain, subdomain, ip), `severity`, `source_id`, `cursor`"),
            ("GET", "https://api.spycloud.io/enterprise-v2/breach/catalog/{id}", "Breach metadata by id"),
        ],
        auth="`X-API-KEY` header with the user's key from the SpyCloud customer portal.",
        env=[("SPYCLOUD_API_KEY", True, "SpyCloud Enterprise Protection API key (paid). Bring your own licence.")],
        rate="429 is documented; no number published in the public docs. Read the response headers and back off.",
        cache="`session` for records. Breach catalogue metadata 24 hours.",
        terms="Commercial licence. Default flags: no on-disk cache of records, metadata only in the store, no STIX export. SpyCloud can return hashed values if hashing is enabled on the key; prefer that.",
        terms_flags=("session", "metadata", False),
        hosts=["api.spycloud.io"],
        notes="The watchlist lives on SpyCloud's side; `doctor` compares it with the local org-exposure watchlist and reports domains missing from either.",
        verified="Vendor docs (docs.spycloud.com): API guidelines name the `X-API-KEY` header; reference pages document the watchlist and breach catalogue endpoints and parameters above.",
        tools=[
            ("spycloud_watchlist_exposure", "Exposure records for watchlist domains since a date, summarised by type and severity. Credential values are redacted before return.", obj({"since": SINCE, "watchlist_type": {"enum": ["email", "domain", "subdomain", "ip"]}, "type": {"enum": ["corporate", "infected", "email_domain", "target_domain"]}, "limit": LIMIT(100, 1000)})),
            ("spycloud_breach_info", "Metadata for one breach source: title, publish date, record count, data classes.", obj({"breach_id": {"type": S}}, ["breach_id"])),
        ],
        fixtures=["watchlist_synthetic.json (synthetic, fake addresses on example.com.au)", "breach_catalog_synthetic.json (synthetic)", "spycloud_403.json", "spycloud_429.json"],
    ),
    dict(
        key="upguard", server="upguard", name="UpGuard CyberRisk (identity breaches, data leaks and typosquats; Australian vendor)",
        group="Attack surface and brand monitoring", milestone=M_V02, priority="p2", paid=True,
        docs="https://cyber-risk.upguard.com/api/docs",
        endpoints=[
            ("GET", "https://cyber-risk.upguard.com/api/public/breaches", "Breached identities ordered by last breached date (permission `IdentityBreaches`)"),
            ("GET", "https://cyber-risk.upguard.com/api/public/breach?id=...", "One identity breach"),
            ("GET", "https://cyber-risk.upguard.com/api/public/dataleaks/disclosures", "Data leak disclosures; filters `min_time`, `max_time`, `statuses` (permission `DataLeaks`)"),
            ("GET", "https://cyber-risk.upguard.com/api/public/typosquat , /typosquat/details?domain=", "Typosquat domains for enabled domains (permission `BreachRisk`)"),
        ],
        auth="`Authorization` header set to the API key itself (no `Bearer` prefix). Each key carries the permissions chosen when it was created.",
        env=[("UPGUARD_API_KEY", True, "UpGuard CyberRisk API key with read permissions only (paid). Bring your own licence.")],
        rate="429 is documented; no number published. Back off on 429.",
        cache="Typosquat lists 12 hours. Breach and data leak records `session` by default.",
        terms="Commercial licence. Default flags: metadata in the store, no STIX export. Typosquat domains are the user's own monitoring results and may be exported if the user allows it.",
        terms_flags=("ttl", "metadata", False),
        hosts=["cyber-risk.upguard.com"],
        notes="One of the three v0.2 vendors, and an Australian vendor (headquartered in Hobart). Covers brand and attack surface signals the other exposure feeds do not: lookalike domains and leaked data disclosures. Create the key with only the read permissions these tools need; `doctor` warns if a write endpoint answers.",
        verified="Vendor docs (cyber-risk.upguard.com/api/docs, API version 1.12 on the page): base URL, `Authorization` header and the permissions per endpoint. `/api/public/breaches` returned 403 to a bad key from the build box on 16 October 2026.",
        tools=[
            ("upguard_identity_breaches", "Breached identities for the account's domains, with breach name, date and data classes. No values.", obj({"limit": LIMIT(100, 1000)})),
            ("upguard_data_leaks", "Data leak disclosures in a time window, with status.", obj({"since": {"type": S, "format": "date-time"}, "until": {"type": S, "format": "date-time"}, "statuses": {"type": "array", "items": {"enum": ["Disclosed", "Acknowledged", "Investigating", "Remediating", "ClosedNoIssue", "ClosedRiskAccepted", "ClosedFixedUnverified", "ClosedFixedVerified"]}}})),
            ("upguard_typosquats", "Typosquat and lookalike domains for one enabled domain.", obj({"domain": DOMAIN}, ["domain"])),
        ],
        fixtures=["breaches_synthetic.json (synthetic)", "disclosures_synthetic.json (synthetic)", "typosquat_details_synthetic.json (synthetic lookalikes of example.com.au)", "upguard_403.json", "upguard_404_domain_not_enabled.json"],
    ),
    dict(
        key="ransomware-live", server="ransomlive", name="ransomware.live victim tracker (free, filter by country AU)",
        group="Ransomware victim monitoring (free)", milestone=M_V02, priority="p2", paid=False,
        docs="https://www.ransomware.live/apidocs",
        endpoints=[
            ("GET", "https://api-pro.ransomware.live/victims/?country=AU", "Victims filtered by ISO country code, sector, group, year and month (at least one filter required)"),
            ("GET", "https://api-pro.ransomware.live/victims/recent", "Recent victims"),
            ("GET", "https://api-pro.ransomware.live/victims/search", "Search by keyword"),
            ("GET", "https://api-pro.ransomware.live/csirt/AU", "National CERT contact for a country"),
            ("GET", "https://api.ransomware.live/v2/recentvictims", "Unauthenticated v2 fallback; filter `country == AU` client side"),
        ],
        auth="Free. The PRO API needs a free key in the `X-API-KEY` header (from ransomware.live/my). The v2 API needs no key.",
        env=[("RANSOMWARE_LIVE_API_KEY", False, "Free key for the PRO API. Without it the connector uses the v2 API.")],
        rate="PRO API: 500,000 requests a month per key, 429 beyond. v2: rate limited, no number published. Self-imposed: one poll an hour.",
        cache="1 hour.",
        terms="Free community project. Victim entries are claims scraped from criminal leak sites, not confirmed incidents. Check the site's terms before redistributing; default flags: store metadata, no STIX export of victim names.",
        terms_flags=("ttl", "metadata", False),
        hosts=["api-pro.ransomware.live", "api.ransomware.live"],
        notes="Clearly free, not premium; it sits in this epic because it feeds the same AU org exposure watch. The v2 docs list `/countryvictims/<code>`, but that path returned 404 from the build box on 16 October 2026, so the PRO `/victims/?country=AU` filter is primary and v2 with a client-side filter is the fallback. RansomLook (ransomlook.io) has a similar free API without a documented country filter; not wired.",
        verified="PRO API OpenAPI spec (api-pro.ransomware.live/swagger.json): `X-API-KEY`, 500,000 requests a month, `country` filter. v2 `/info` and `/recentvictims` returned 200 without a key on 16 October 2026.",
        tools=[
            ("ransom_au_victims", "Leak-site claims naming Australian organisations, newest first, each marked as an unverified claim.", obj({"since": SINCE, "sector": {"type": S}, "group": {"type": S}, "limit": LIMIT(50, 500)})),
            ("ransom_watchlist_match", "Match recent claims against the org-exposure watchlist (names, brands, domains).", obj({"days": {"type": "integer", "minimum": 1, "maximum": 90, "default": 7}})),
        ],
        fixtures=["victims_country_AU_synthetic.json (synthetic: invented organisation names, example domains)", "recentvictims_v2_synthetic.json (synthetic)", "ransomlive_429.json"],
        not_default_off=True,
    ),
    dict(
        key="recorded-future", server="recordedfuture", name="Recorded Future (identity exposure, dark web and ransomware brand alerts, domain abuse, risk lists, official MCP)",
        group="Threat intelligence platforms", milestone=M_V02, priority="p1", paid=True,
        docs="https://docs.recordedfuture.com/reference/get-started",
        endpoints=[
            ("POST", "https://api.recordedfuture.com/identity/credentials/search", "Identity Intelligence: compromised identities for up to 100 domains across breach dumps and stealer logs; `domain_types` Email and/or Authorization; `filter`; `limit` 0 to 1,000; `offset`"),
            ("POST", "https://api.recordedfuture.com/identity/detections", "Identity Intelligence: exposure detections for the organisation, with a `novel_only` filter and malware family attribution"),
            ("POST", "https://api.recordedfuture.com/identity/credentials/lookup", "Identity Intelligence: exposure history for given identities; accepts SHA1-hashed emails (`subjects_sha1`) for privacy-preserving lookups"),
            ("POST", "https://api.recordedfuture.com/playbook-alert/search", "Playbook alerts; body filters `category`, `statuses`, `priority`, `entity`, `created_range`, `updated_range`, `limit`, `offset`. Categories in the docs include `identity_novel_exposures`, `domain_abuse`, `third_party_risk`, `code_repo_leakage`, `cyber_vulnerability`, `malicious_sites`, `geopolitics_facility`"),
            ("POST", "https://api.recordedfuture.com/playbook-alert/dark_web_brand/{id}", "Dark Web Brand alert detail: the organisation's brand or assets on forums, markets, Telegram channels and ransomware extortion sites"),
            ("POST", "https://api.recordedfuture.com/playbook-alert/domain_abuse/{id}", "Domain Abuse alert detail: typosquats and phishing domains impersonating the organisation"),
            ("POST", "https://api.recordedfuture.com/playbook-alert/identity_novel_exposures/{id}", "Identity Novel Exposures alert detail"),
            ("GET", "https://api.recordedfuture.com/v2/company/by_domain/{domain}", "Connect API: resolve a watchlist domain to its Company entity with risk score and evidence"),
            ("GET", "https://api.recordedfuture.com/v2/{ip|domain|hash|url|vulnerability}/risklist", "Connect API risk lists (CSV or STIX), filtered by risk rule; matching `stat` endpoints return ETag-only change checks"),
            ("MCP", "https://mcp.recordedfuture.com/mcp", "Official Recorded Future MCP server (generally available). OAuth 2.0 client credentials for an Integration User, or browser authorisation code for a portal user; scoped to one organisation"),
        ],
        auth="REST: `X-RFToken` header; tokens are created by an Enterprise Administrator and entitlements follow licensed modules. MCP: OAuth 2.0 (Integration User client id and secret from the Integration Center, or portal sign-in).",
        env=[("RECORDED_FUTURE_API_TOKEN", True, "REST API token (paid). Bring your own licence."),
             ("RECORDED_FUTURE_ORG_ID", False, "Organisation id for identity endpoints when the token covers several (`organization_id`)."),
             ("RECORDED_FUTURE_MCP_CLIENT_ID", False, "Integration User client id for the official MCP server."),
             ("RECORDED_FUTURE_MCP_CLIENT_SECRET", False, "Integration User client secret.")],
        rate="One unified Daily API Call Limit per subscription covers REST calls and MCP tool calls (one MCP tool call counts as one API call). The guard reads the user's limit from `config.yaml` and keeps the routine share under it. Back off on 429.",
        cache="Identity data `session` only. Playbook alert metadata 1 hour. Risk lists: fetched only when the `stat` ETag changes, cached until the next change if the contract allows local use.",
        terms="Commercial licence; MCP access needs a subscription with unlimited integrations (pilot access for others runs to 31 December 2026, per the vendor). Default flags: identity and alert metadata only in the store, no STIX export of vendor content, no sharing outside the profile. Risk lists stay inside the profile.",
        terms_flags=("session", "metadata", False),
        hosts=["api.recordedfuture.com", "mcp.recordedfuture.com"],
        notes="""Maintainer priority: a v0.2 vendor at p1.

Two paths, both off by default:
1. **First-party REST tools** (primary). Narrow, read-only tools over Identity Intelligence, Playbook Alerts and the Connect API, built on the shared client so terms flags, redaction and the budget guard apply to every byte. This is what the AU org exposure skill and routine call.
2. **Official MCP wrap** (optional). A `recordedfuture_mcp` entry pointing at `https://mcp.recordedfuture.com/mcp` with `auth: oauth`, `trust: untrusted` and a `tools.include` list frozen at build time from the vendor's published tool list (the `whoami` tool confirms the connected organisation). Only read tools are included; any tool that updates alerts or creates takedowns stays excluded. Use it for analyst questions the narrow tools do not cover.

AU org exposure mapping:
- Watchlist domains and email domains go to `identity/credentials/search` (both `Email` and `Authorization` domain types, so customer logins on the user's own sites show up) and `identity/detections` with `novel_only: true` for the alert routine.
- Watchlist brands and subsidiaries map to the organisation's Recorded Future watch lists (configured in the portal); the connector reads `dark_web_brand` and `domain_abuse` playbook alerts and matches their entities back to watchlist entries. Ransomware extortion site mentions inside Dark Web Brand alerts become `leak_site_claim` findings marked `vendor_reported`.
- Each watchlist domain is resolved once with `company/by_domain` so briefings can show Recorded Future's company risk score next to the finding.
- `third_party_risk` alerts are read only for suppliers the user lists under `suppliers:` in the watchlist (optional), and are never alerted on as the user's own exposure.

Confirm every path, method and body field against docs.recordedfuture.com at build time; the vendor asks integrators to treat those docs as the only source.""",
        verified="Vendor docs (docs.recordedfuture.com, pages updated June to September 2026): authentication table (`X-RFToken`, base URLs), Identity Intelligence search, detections and lookup OpenAPI definitions, Playbook Alerts search (body fields and categories), Dark Web Brand and Domain Abuse detail pages (ransomware site mentions named in the Dark Web Brand description), Connect API company by domain and domain risk list. Vendor support centre: MCP overview (server URL, OAuth methods, single-organisation scope) and 'API & MCP Access & Usage' (unified daily limit, one tool call equals one API call). From the build box on 16 October 2026 a bad token got 401 from the REST API, and `mcp.recordedfuture.com/mcp` answered 401 without auth.",
        tools=[
            ("rf_identity_exposure", "Compromised identities for watchlist domains: counts by exposure type (Email, Authorization), malware family and first and last seen. Returns no passwords, cookies or full usernames.", obj({"domains": DOMAINS, "domain_types": {"type": "array", "items": {"enum": ["Email", "Authorization"]}, "default": ["Email", "Authorization"]}, "limit": LIMIT(100, 1000)}, ["domains"])),
            ("rf_identity_detections", "New (novel) identity detections for the organisation since a date, grouped by watchlist domain and malware family. Used by the alert routine.", obj({"since": SINCE, "novel_only": {"type": "boolean", "default": True}, "limit": LIMIT(100, 1000)})),
            ("rf_identity_lookup_hashed", "Exposure history for specific staff identities, sent only as SHA1 hashes of email addresses. Needs approval in the guard.", obj({"emails_sha1": {"type": "array", "items": {"type": S, "pattern": "^[a-f0-9]{40}$"}, "minItems": 1, "maxItems": 100}}, ["emails_sha1"])),
            ("rf_brand_alerts", "Dark Web Brand and Domain Abuse playbook alerts since a date, matched to watchlist entries, with alert id, category, priority, status and summary. Ransomware site mentions are flagged.", obj({"since": SINCE, "categories": {"type": "array", "items": {"enum": ["dark_web_brand", "domain_abuse", "identity_novel_exposures", "code_repo_leakage", "third_party_risk"]}, "default": ["dark_web_brand", "domain_abuse"]}, "statuses": {"type": "array", "items": {"type": S}}, "limit": LIMIT(50, 250)})),
            ("rf_alert_detail", "Detail panels for one playbook alert, with untrusted text wrapped and screenshots not fetched.", obj({"category": {"enum": ["dark_web_brand", "domain_abuse", "identity_novel_exposures"]}, "alert_id": {"type": S}}, ["category", "alert_id"])),
            ("rf_company_by_domain", "Company entity, risk score and top triggered rules for a watchlist domain.", obj({"domain": DOMAIN}, ["domain"])),
            ("rf_risklist_status", "Whether a risk list changed since the last fetch (ETag via the stat endpoint), and when it was last pulled.", obj({"entity_type": {"enum": ["ip", "domain", "hash", "url", "vulnerability"]}, "risk_rule": {"type": S, "description": "Risk rule name; default list when omitted"}}, ["entity_type"])),
        ],
        fixtures=["identity_search_synthetic.json (synthetic: example.com.au, fake malware family counts)", "identity_detections_novel_synthetic.json (synthetic)", "playbook_search_dark_web_brand_synthetic.json (synthetic, includes a ransomware site mention of an invented company)", "domain_abuse_detail_synthetic.json (synthetic lookalikes of example.com.au)", "company_by_domain_synthetic.json (synthetic)", "domain_risklist_stat_304 (ETag unchanged)", "rf_401.json", "rf_429.json", "mcp_tools_list.json (recorded tools/list from a test organisation, names only)"],
        extra_tests=[
            "Hashing test: `rf_identity_lookup_hashed` refuses plain email input and sends only lower-case SHA1 hex.",
            "Category test: alerts outside the requested categories are dropped; `third_party_risk` alerts for suppliers never become own-organisation findings.",
            "Budget test: a routine run stops when its share of the Daily API Call Limit is used, and MCP tool calls count one for one.",
            "MCP filter test: against the recorded tools list, only included read tools register; any tool whose name implies update, create or takedown is rejected by the render step.",
        ],
        extra_criteria=[
            "AU org exposure skill returns Recorded Future identity, dark web brand and domain abuse findings for a synthetic watchlist end to end.",
            "Alert routine raises one alert per new novel detection or new playbook alert, never repeats.",
            "The optional MCP entry renders with `auth: oauth`, `enabled: false` and a frozen `tools.include` list, and `doctor` reports the connected organisation via `whoami`.",
        ],
    ),
    dict(
        key="flashpoint", server="flashpoint", name="Flashpoint Ignite (compromised credentials and indicators)",
        group="Threat intelligence platforms", milestone=M_V10, priority="p3", paid=True,
        docs="https://docs.flashpoint.io/",
        endpoints=[
            ("GET", "https://api.flashpoint.io/technical-intelligence/v2/indicators", "Indicators"),
            ("GET", "(credential sightings search path: confirm in docs.flashpoint.io)", "Compromised credential sightings with queries such as `+basetypes:credential-sighting +domain.keyword:<domain> +is_fresh:true`"),
        ],
        auth="Bearer token (Ignite API key).",
        env=[("FLASHPOINT_API_TOKEN", True, "Flashpoint Ignite API token (paid). Bring your own licence.")],
        rate="Not published publicly. Back off on 429.",
        cache="`session`.",
        terms="Commercial licence. Default flags: metadata only, no STIX export.",
        terms_flags=("session", "metadata", False),
        hosts=["api.flashpoint.io"],
        notes="Flashpoint's documentation portal renders with script and could not be read by the fetch tools, so the credential search path is left to confirm at build time. Do not code against the vendor-integration examples without checking the portal.",
        verified="`technical-intelligence/v2/indicators` returned 401 without a token from the build box on 16 October 2026. Query syntax and bearer auth from vendor-published integrations (Cortex XSOAR, Splunk SOAR); the portal itself was not readable.",
        tools=[
            ("flashpoint_credential_exposure", "Fresh compromised credential sightings for a watchlist domain, as counts and first-seen dates.", obj({"domain": DOMAIN, "since": SINCE, "fresh_only": {"type": "boolean", "default": True}}, ["domain"])),
            ("flashpoint_indicator", "Indicator context by value.", obj({"value": {"type": S, "minLength": 3}}, ["value"])),
        ],
        fixtures=["credential_sightings_synthetic.json (synthetic)", "indicator_synthetic.json (synthetic)", "flashpoint_401.json"],
    ),
    dict(
        key="intel471", server="intel471", name="Intel 471 Titan (watchers, alerts, credentials and breach alerts)",
        group="Threat intelligence platforms", milestone=M_V10, priority="p3", paid=True,
        docs="https://github.com/intel471/titan-client-python",
        endpoints=[
            ("GET", "https://api.intel471.com/v1/alerts", "Watcher alerts; `count`, `from`, `until`, `offset`, `watcher_group`"),
            ("GET", "https://api.intel471.com/v1/watcherGroups , /watcherGroups/{uid}/watchers", "Watcher configuration (read only here)"),
            ("GET", "https://api.intel471.com/v1/credentials , /credentials/occurrences , /credentialSets", "Credential intelligence"),
            ("GET", "https://api.intel471.com/v1/breachAlerts", "Breach alerts"),
        ],
        auth="HTTP Basic: the registered Intel 471 email as the username and the API key as the password.",
        env=[("INTEL471_EMAIL", True, "Registered account email."), ("INTEL471_API_KEY", True, "Titan API key (paid). Bring your own licence.")],
        rate="Not published in the client README. Back off on 429.",
        cache="`session`; the official client's own 10 hour cache is switched off so the terms flags decide.",
        terms="Commercial licence. Default flags: metadata only, no STIX export.",
        terms_flags=("session", "metadata", False),
        hosts=["api.intel471.com"],
        notes="Watchers are configured in Titan; this connector only reads alerts and matches them to the local watchlist. Breach alerts often name victims; handle under the privacy note.",
        verified="Vendor's public OpenAPI-generated client (intel471/titan-client-python) lists the endpoints above and Basic auth. `api.intel471.com/v1/` returned 401 from the build box on 16 October 2026.",
        tools=[
            ("intel471_watcher_alerts", "Recent watcher alerts with watcher name, source type and timestamp.", obj({"since": SINCE, "watcher_group": {"type": S}, "limit": LIMIT(100, 1000)})),
            ("intel471_breach_alerts", "Breach alerts mentioning watchlist names or domains.", obj({"query": {"type": S, "minLength": 2}, "since": SINCE}, ["query"])),
            ("intel471_credential_exposure", "Credential occurrences for a watchlist domain, as counts.", obj({"domain": DOMAIN, "since": SINCE}, ["domain"])),
        ],
        fixtures=["alerts_synthetic.json (synthetic)", "breach_alerts_synthetic.json (synthetic)", "credentials_occurrences_synthetic.json (synthetic)", "intel471_401.json"],
    ),
    dict(
        key="google-ti-dtm", server="gtidtm", name="Google Threat Intelligence Digital Threat Monitoring (formerly Mandiant)",
        group="Dark web and leak monitoring", milestone=M_V10, priority="p3", paid=True,
        docs="https://gtidocs.virustotal.com/",
        endpoints=[
            ("GET", "https://www.virustotal.com/api/v3/dtm/alerts", "DTM alerts; filters include `monitor_id`, `status`, `severity`, `alert_type`, `since`, `until`, `search`, `match_value`; paged with the `Link` header"),
            ("GET", "https://www.virustotal.com/api/v3/dtm/monitors", "Monitors (read only here)"),
        ],
        auth="`x-apikey` header with a Google Threat Intelligence key, plus an `x-tool` header naming the integration (for example `hermes-cyber-au.v0.x`).",
        env=[("GTI_API_KEY", True, "Google Threat Intelligence API key with DTM entitlement (paid). Bring your own licence.")],
        rate="Per licence. Back off on 429.",
        cache="`session`.",
        terms="Commercial licence. Default flags: metadata only, no STIX export.",
        terms_flags=("session", "metadata", False),
        hosts=["www.virustotal.com"],
        notes="Mandiant Advantage DTM moved to `www.virustotal.com/api/v3/dtm/` under Google TI. Shares the host with the VirusTotal connector but uses a different key and server entry; never reuse a Public API key here.",
        verified="Vendor docs (gtidocs.virustotal.com): DTM pagination page, the Mandiant migration guide and the DTM OpenAPI reference. `x-tool` from the vendor's public `VirusTotal/gti-dev-kit`.",
        tools=[
            ("gti_dtm_alerts", "DTM alerts since a date, with monitor, severity, alert type and matched value.", obj({"since": SINCE, "severity": {"enum": ["low", "medium", "high"]}, "status": {"type": S}, "limit": LIMIT(50, 500)})),
            ("gti_dtm_monitors", "Configured monitors and what each watches.", obj({})),
        ],
        fixtures=["dtm_alerts_synthetic.json (synthetic)", "dtm_monitors_synthetic.json (synthetic)", "dtm_link_header_page2 (synthetic)", "gti_401.json"],
    ),
    dict(
        key="crowdstrike-recon", server="csrecon", name="CrowdStrike Falcon Adversary Intelligence Recon (dark web monitoring notifications)",
        group="Dark web and leak monitoring", milestone=M_V10, priority="p3", paid=True,
        docs="https://developer.crowdstrike.com/api-reference/collections/recon/",
        endpoints=[
            ("POST", "https://api.crowdstrike.com/oauth2/token", "OAuth2 client credentials token (use the base URL for the customer's cloud)"),
            ("GET", "Recon notifications query and entities endpoints (FalconPy `query_notifications`, `get_notifications`)", "Notifications raised by monitoring rules"),
            ("GET", "Recon rules query and entities endpoints (FalconPy `query_rules`, `get_rules`)", "Monitoring rules (read only here)"),
        ],
        auth="OAuth2 client credentials from an API client created in Falcon with read scope for Recon monitoring rules only.",
        env=[("FALCON_CLIENT_ID", True, "API client id (paid licence). Bring your own."), ("FALCON_CLIENT_SECRET", True, "API client secret."), ("FALCON_BASE_URL", False, "Cloud base URL if not the default.")],
        rate="Per Falcon API limits, returned in headers. Back off on 429.",
        cache="`session`.",
        terms="Commercial licence. Default flags: metadata only, no STIX export.",
        terms_flags=("session", "metadata", False),
        hosts=["api.crowdstrike.com"],
        notes="Use the official FalconPy SDK (public `CrowdStrike/falconpy`) rather than hand-written calls. Creating rules is out of scope; rules are managed in Falcon.",
        verified="Vendor developer centre Recon collection page and FalconPy `recon.py`. The token endpoint returned 401 from the build box on 16 October 2026.",
        tools=[
            ("cs_recon_notifications", "Recon notifications since a date with rule name, topic and match summary.", obj({"since": SINCE, "limit": LIMIT(100, 500)})),
            ("cs_recon_rules", "Monitoring rules and their topics.", obj({})),
        ],
        fixtures=["notifications_synthetic.json (synthetic)", "rules_synthetic.json (synthetic)", "oauth_401.json"],
    ),
    dict(
        key="socradar", server="socradar", name="SOCRadar (company incidents: dark web, leaks, brand and attack surface)",
        group="Dark web and leak monitoring", milestone=M_V10, priority="p3", paid=True,
        docs="https://socradar.io/socradar-apis/",
        endpoints=[("GET", "https://platform.socradar.com/api/company/{company_id}/incidents/v4", "Company incidents; filters `start_date`, `end_date`, `status`, `severity`, alarm types, `page`, `limit`")],
        auth="Company API key in the `Api-Key` header, plus the numeric company id.",
        env=[("SOCRADAR_API_KEY", True, "Company API key (paid). Bring your own licence."), ("SOCRADAR_COMPANY_ID", True, "Numeric company id.")],
        rate="Not published publicly. Back off on 429.",
        cache="`session`.",
        terms="Commercial licence. Default flags: metadata only, no STIX export.",
        terms_flags=("session", "metadata", False),
        hosts=["platform.socradar.com"],
        notes="One endpoint covers dark web mentions, leaked credentials, brand impersonation and attack surface alarms, so the connector maps alarm types onto the common exposure kinds.",
        verified="Vendor API page (socradar.io/socradar-apis) and vendor-published integrations (Elastic, Cortex XSOAR) for the incidents v4 path and `Api-Key` header. Confirm parameters in the customer portal at build time.",
        tools=[("socradar_incidents", "Company incidents in a date range, mapped to exposure kinds.", obj({"since": SINCE, "until": SINCE, "severity": {"type": S}, "limit": LIMIT(100, 500)}))],
        fixtures=["incidents_v4_synthetic.json (synthetic)", "socradar_401.json"],
    ),
    dict(
        key="darkowl", server="darkowl", name="DarkOwl Vision (dark web search)",
        group="Dark web and leak monitoring", milestone=M_V10, priority="p3", paid=True,
        docs="https://support.darkowl.com/knowledge-base/search-api-documentation",
        endpoints=[("GET", "https://api.darkowl.com/api/v1/search?q=...", "Search the dark web index; `sort`, `offset`, `highlight` and filters")],
        auth="HMAC-SHA1 request signing: sign method, path and a UTC `Date` header with the private key and send `Authorization: OWL <public key>:<base64 signature>`.",
        env=[("DARKOWL_PUBLIC_KEY", True, "Public key (paid). Bring your own licence."), ("DARKOWL_PRIVATE_KEY", True, "Private key used only to sign; never logged.")],
        rate="Per licence. Back off on 429.",
        cache="`session`.",
        terms="Commercial licence. Default flags: no snippets stored, counts and links only, no STIX export.",
        terms_flags=("session", "metadata", False),
        hosts=["api.darkowl.com"],
        notes="Search returns dark web text, which is hostile content by definition: wrap every snippet with `untrusted_text`, cap length, never follow links.",
        verified="Vendor support knowledge base: search API documentation and the authorisation header calculation page. `api.darkowl.com` answered 403 to an unsigned request from the build box on 16 October 2026.",
        tools=[("darkowl_search_watchlist", "Search for watchlist names, brands and domains; returns hit counts, first and last seen dates and source types.", obj({"terms": {"type": "array", "items": {"type": S, "minLength": 3}, "minItems": 1, "maxItems": 20}, "since": SINCE}, ["terms"]))],
        fixtures=["search_synthetic.json (synthetic)", "signature_vector.json (known-answer test for the HMAC)", "darkowl_403.json"],
        extra_tests=["Known-answer test for the signature with a published-style vector generated locally; the private key never appears in logs."],
    ),
    dict(
        key="flare", server="flare", name="Flare threat exposure management (leaked credentials, stealer logs, leak and ransomware sites, dark web, official MCP)",
        group="Dark web and leak monitoring", milestone=M_V02, priority="p1", paid=True,
        docs="https://api.docs.flare.io/introduction/getting-started",
        endpoints=[
            ("POST", "https://api.flare.io/tokens/generate", "Exchange the API key (raw `Authorization` header) for a 1 hour API token; optional `tenant_id`"),
            ("GET", "https://api.flare.io/tokens/test", "Check a token"),
            ("POST", "https://api.flare.io/firework/v4/events/tenant/_search", "Events matching the tenant's monitored identifiers; filters `severity`, `type`, `estimated_created_at`; paged with `from` and `next`"),
            ("POST", "https://api.flare.io/firework/v4/events/identifiers/{identifier_id}/_search", "Events for one identifier; also filters `tags`, `status`, `is_ignored`, `is_remediated`"),
            ("POST", "https://api.flare.io/firework/v4/events/identifier_groups/{identifier_group_id}/_search", "Events for an identifier group"),
            ("GET", "https://api.flare.io/firework/v4/identifiers/", "Monitored identifiers (read only here)"),
            ("POST", "https://api.flare.io/firework/v4/credentials/global/_search", "Global credential search by domain, auth domain, email, password or keyword; counts against the monthly Global Search quota"),
            ("POST", "https://api.flare.io/firework/v4/events/global/_search", "Global event search; event types include `stealer_log`, `ransomleak`, `leak`, `illicit_networks`, `listing`, `forum_content`, `chat_message`, `paste`, `source_code`, `buckets`; counts against the quota"),
            ("MCP", "https://api.flare.io/mcp", "Official Flare API MCP server (beta). OAuth or API key in `Authorization`; tenant via `X-Flare-Tenant-Id`"),
        ],
        auth="API key (from the Flare profile page, ideally a Restricted key with Read Tenant only and an expiry date) exchanged at `/tokens/generate` for a 1 hour bearer token. The connector refreshes the token before expiry and never logs either value.",
        env=[("FLARE_API_KEY", True, "Restricted Flare API key with Read Tenant permission and an expiry date (paid). Bring your own licence."),
             ("FLARE_TENANT_ID", False, "Tenant id when the key can reach more than one tenant.")],
        rate="Per organisation: Basic tier 4 requests a second, Search tier 1 request a second; 429 `RATELIMIT_REACHED`, wait 10 seconds before retrying. Global Search has a monthly quota; each response carries `X-Flare-Global-Searches-Remaining`, which the budget guard records.",
        cache="`session` for events and credentials. Identifier list 1 hour.",
        terms="Commercial licence. Default flags: event metadata only in the store, no STIX export of Flare content, no sharing outside the profile.",
        terms_flags=("session", "metadata", False),
        hosts=["api.flare.io"],
        notes="""Maintainer priority: sits next to Recorded Future as a v0.2 vendor at p1.

Two paths, both off by default:
1. **First-party REST tools** (primary), built on the shared client with token refresh, the Search tier limiter (1 a second), the budget guard and redaction. Tenant searches are preferred because they match the user's own identifiers and do not spend Global Search quota; global searches need approval in the guard above a per-day count the user sets.
2. **Official MCP wrap** (optional, beta). A `flare_mcp` entry at `https://api.flare.io/mcp` with `trust: untrusted` and `tools.include` limited to read tools from the vendor's list: `search_tenant`, `search_global`, `search_validate_search_query`, `events_get_event`, `events_expand_event`, `events_get_event_type`, `identifiers_list`, `identifiers_explain_event`, `identifier_groups_list`, `matching_policies_list`, `severity_rules_list`, `entities_search`, `profile_get`. Tools that create or change identifiers, groups, matching policies or severity rules stay excluded. The vendor marks the server beta; pin the tool list and let connector health open a drift issue when it changes.

AU org exposure mapping:
- Flare monitors identifiers configured in the tenant (domains, brand keywords and so on). `doctor --premium` lists them read only and compares them with the local org-exposure watchlist, reporting watchlist entries Flare is not monitoring so the user can add them in Flare. The connector never creates identifiers.
- The alert routine runs `events/tenant/_search` since the last run, filtered to types `stealer_log`, `ransomleak`, `leak`, `illicit_networks`, `listing` and the credential event types, and maps them to `ExposureFinding` kinds (`infostealer_credential`, `leak_site_claim`, `breach_credential`, `dark_web_mention`).
- `ransomleak` events naming the organisation become `leak_site_claim` findings marked `vendor_reported`, and the briefing says the claim is unconfirmed.
- Credential search is by domain only by default (`DomainQuery` on watchlist email domains). Password and email queries are not exposed as tools.""",
        verified="Vendor docs (api.docs.flare.io): authentication guide (API key to 1 hour token, bearer use, restricted keys and expiry), rate limits and quotas page (4 and 1 requests a second, 429 handling, `X-Flare-Global-Searches-Remaining`), Search Credentials, Search Events, List Identifier Events and the tenant events guide (paths above), and the API MCP page (server URL, OAuth or API key, `X-Flare-Tenant-Id`, tool list). Flare's July 2026 release notes announce the MCP beta. From the build box on 16 October 2026, `https://api.flare.io/mcp` answered 401 without auth.",
        tools=[
            ("flare_tenant_exposure", "Events matching the tenant's identifiers since a date, mapped to exposure kinds, with severity, type, identifier and estimated creation date. No credential values.", obj({"since": SINCE, "types": {"type": "array", "items": {"enum": ["stealer_log", "ransomleak", "leak", "illicit_networks", "listing", "forum_content", "chat_message", "paste", "source_code", "buckets", "infected_devices", "valid_credential"]}}, "min_severity": {"enum": ["info", "low", "medium", "high", "critical"]}, "limit": LIMIT(100, 1000)})),
            ("flare_identifier_events", "Events for one monitored identifier, for drill-down from a briefing item.", obj({"identifier_id": {"type": "integer"}, "since": SINCE, "include_remediated": {"type": "boolean", "default": False}}, ["identifier_id"])),
            ("flare_identifiers", "Identifiers monitored in the tenant, compared with the local watchlist (missing on either side).", obj({})),
            ("flare_domain_credentials", "Counts of leaked credentials for a watchlist email domain from global credential search, by source type and imported date. Spends Global Search quota; asks first above the user's daily threshold.", obj({"domain": DOMAIN, "since": SINCE}, ["domain"])),
            ("flare_quota_status", "Global Search searches remaining this month, from the last response header.", obj({})),
        ],
        fixtures=["tenant_events_synthetic.json (synthetic: stealer_log, ransomleak and leak events for example.com.au)", "identifier_events_synthetic.json (synthetic)", "identifiers_synthetic.json (synthetic)", "credentials_global_search_synthetic.json (synthetic, counts only)", "token_generate_synthetic.json (synthetic token, expiry in 1 hour)", "flare_429_ratelimit.json", "flare_401.json", "mcp_tools_list.json (names from the vendor's published list)"],
        extra_tests=[
            "Token test: the client refreshes before the 1 hour expiry and retries once on 401; neither key nor token appears in logs or cassettes.",
            "Limiter test: two search calls inside a second are spaced by the Search tier limiter; a 429 waits 10 seconds.",
            "Quota test: `X-Flare-Global-Searches-Remaining` is recorded and the guard blocks global searches below a user-set floor.",
            "MCP filter test: write tools (`identifiers_create`, `identifier_groups_create`, `matching_policies_create`, `severity_rules_create`) never register.",
        ],
        extra_criteria=[
            "AU org exposure skill returns Flare stealer log, leak and ransomware leak findings for a synthetic watchlist end to end.",
            "`doctor --premium` lists watchlist entries Flare does not monitor, without changing anything in Flare.",
            "The optional MCP entry renders with `enabled: false` and only the read tools listed above.",
        ],
    ),
]
