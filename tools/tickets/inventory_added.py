"""Connectors added after the first filing, for sources found by a second, independent inventory
(checked 16 October 2026) that the first inventory did not cover. Same shape as inventory.CONNECTORS."""
from __future__ import annotations

from common import M_V01, M_V02, M_V10, hsrc
from inventory import obj, S, CVE, DATE, LIMIT, IP

HOSTNAME = {"type": S, "format": "hostname"}
URL = {"type": S, "format": "uri"}
HASH = {"type": S, "pattern": "^([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$"}
SECOND = "Listed by a second inventory on 16 October 2026"

ADDED = [
    dict(
        key="virustotal", server="virustotal", name="VirusTotal via the official VirusTotal MCP server",
        group="Global threat intelligence", milestone=M_V01, priority="p1",
        docs="https://docs.virustotal.com/reference/overview",
        endpoints=[
            ("MCP", "https://github.com/VirusTotal/virustotal-mcp", "Official VirusTotal MCP server, run locally over stdio. Pin a release or commit"),
            ("GET", "https://www.virustotal.com/api/v3/files/{hash} , /urls/{id} , /domains/{domain} , /ip_addresses/{ip}", "Underlying API v3 reports"),
        ],
        auth="`x-apikey` header with the user's own VirusTotal key.",
        env=[("VIRUSTOTAL_API_KEY", True, "The user's own VirusTotal API key. Never shared or shipped.")],
        rate="Public API: 4 requests a minute and 500 a day. Premium keys have their own quota.",
        cache="Reports cached 24 hours in the plugin middleware, keyed by indicator, so repeat questions do not spend quota.",
        terms="The VirusTotal Public API must not be used in commercial products or services, or in business workflows that do not contribute new files. Premium API is paid. Show this in the skill text and docs.",
        default_off="VirusTotal Public API terms rule out commercial use (see Terms). The server ships with `enabled: false` and users bring their own key, Public or Premium.",
        hosts=["www.virustotal.com", "ai.virustotal.com"],
        notes="Zero-build quick win for v0.1: wrap the official server rather than writing a client. Reports only. Upload, rescan, comment and vote tools are excluded by `tools.include`. Confirm exact tool names from the pinned release, then freeze them in `mcp/virustotal/expected_tools.txt`.",
        verified=f"`/api/v3/ip_addresses/8.8.8.8` returned 401 without a key from the build box on 16 October 2026. Repository `VirusTotal/virustotal-mcp` is public. {SECOND}, which also read the Public API limits and terms.",
        config="""```yaml
mcp_servers:
  virustotal:
    command: "<PROFILE_HOME>/mcp/vendor/virustotal-mcp/<pinned launcher>"   # set from the pinned release's README
    env:
      VIRUSTOTAL_API_KEY: "${VIRUSTOTAL_API_KEY}"
    tools:
      include: ["<file report tool>", "<url report tool>", "<domain report tool>", "<ip report tool>"]   # exact names frozen at build time
    enabled: false        # Public API terms are non-commercial; the user switches it on
    lazy: true
    timeout: 60
    trust: untrusted
```
Field names from """ + hsrc('website/docs/reference/mcp-config-reference.md') + ". Stdio servers get a filtered environment, so the key must be passed through `env`.",
        files=["mcp/servers.yaml (entry `virustotal`, wrap)", "mcp/vendor/virustotal-mcp.lock (pinned version and checksum)", "mcp/virustotal/expected_tools.txt", "mcp/virustotal/tests/test_virustotal_wrap.py", "mcp/virustotal/SOURCE.md", "docs/connectors/virustotal.md (generated)"],
        tools=[("(wrapped tools)", "Report lookups only: file by hash, URL, domain and IP. Each answer carries detection counts, first and last analysis dates and a permalink. Upload, rescan and community write tools stay excluded.", None)],
        fixtures=["file_report_known_bad.json", "domain_report_clean.json", "vt_401.json", "vt_429_quota.json", "tools_list.json (recorded tools/list)"],
        wrap=True,
        extra_tests=["Filter test: against the recorded `tools/list`, only the four report tools register.", "Quota test: the middleware budget refuses the fifth call inside a minute with a clear message, before the upstream 429."],
        extra_criteria=["No upload, rescan, comment or vote tool is registered."],
    ),
    dict(
        key="hibp", server="hibp", name="Have I Been Pwned via the official HIBP MCP server",
        group="Global threat intelligence", milestone=M_V01, priority="p1",
        docs="https://haveibeenpwned.com/API/v3",
        endpoints=[
            ("MCP", "https://haveibeenpwned.com/mcp", "Official remote MCP server, documented at https://haveibeenpwned.com/Docs/MCP"),
            ("GET", "https://haveibeenpwned.com/api/v3/breaches", "All breach metadata, no key"),
            ("GET", "https://api.pwnedpasswords.com/range/{first 5 SHA-1 hex}", "Pwned Passwords k-anonymity range, no key"),
            ("GET", "https://haveibeenpwned.com/api/v3/breachedaccount/{account}", "Breaches for an email address, paid key or OAuth with a subscription"),
        ],
        auth="None for breach metadata and Pwned Passwords. Email and domain searches, pastes and stealer logs need a paid key or OAuth to an HIBP account with the right subscription.",
        env=[("HIBP_API_KEY", False, "Optional paid key for account and domain searches. Without it only public tools work.")],
        rate="Depends on the key. A 429 carries `retry-after`; honour it.",
        cache="Breach list 24 hours. Account and domain results are not cached on disk (they are personal information).",
        terms="Breach data is CC BY 4.0 with attribution to Have I Been Pwned. No licence or attribution requirement on Pwned Passwords. Do not misrepresent the data source.",
        hosts=["haveibeenpwned.com", "api.pwnedpasswords.com"],
        notes="Zero-build quick win for v0.1, run by an Australian. Public tools work without sign-in. Account and domain lookups touch personal information, so they need a human approval in the `pre_tool_call` guard and results are never written to the intel store. Passwords are never sent: only the 5 character SHA-1 prefix leaves the machine.",
        verified=f"`/api/v3/breaches` returned 200 and `https://haveibeenpwned.com/mcp` returned 406 to a plain GET (exists) from the build box on 16 October 2026. {SECOND}.",
        config="""```yaml
mcp_servers:
  hibp:
    url: "https://haveibeenpwned.com/mcp"
    # headers rendered only when HIBP_API_KEY is set; confirm the header name in the HIBP MCP docs at build time
    # headers:
    #   hibp-api-key: "${HIBP_API_KEY}"
    enabled: true
    lazy: true
    timeout: 60
    trust: untrusted
```
Field names from """ + hsrc('website/docs/reference/mcp-config-reference.md') + ".",
        files=["mcp/servers.yaml (entry `hibp`, wrap)", "mcp/hibp/expected_tools.txt", "mcp/hibp/tests/test_hibp_wrap.py", "mcp/hibp/SOURCE.md", "docs/connectors/hibp.md (generated)"],
        tools=[("(wrapped tools)", "Public: list breaches (optionally by domain), get one breach, Pwned Passwords range lookup. Subscription: breached account, breached domain. Confirm names against the server and freeze them.", None)],
        fixtures=["breaches.json", "range_21BD1.txt", "hibp_401.json", "account-exists (HIBP published test account on hibp-integration-tests.com)", "multiple-breaches (published test account)"],
        wrap=True,
        extra_tests=["Approval test: an account or domain lookup without an approval token is blocked by the guard and logged.", "Privacy test: no email address appears in the intel store, cache or audit log body (hashes only)."],
        extra_criteria=["Account and domain lookups require human approval and are never stored.", "Only HIBP's published test accounts are used in tests."],
    ),
    dict(
        key="github-advisories", server="ghsa", name="GitHub Advisory Database via the GitHub MCP server",
        group="Vulnerability intelligence", milestone=M_V01, priority="p1",
        docs="https://github.com/advisories",
        endpoints=[
            ("MCP", "https://github.com/github/github-mcp-server", "Official GitHub MCP server with the `security_advisories` toolset only"),
            ("GET", "https://api.github.com/advisories", "Underlying REST endpoint for global advisories"),
        ],
        auth="Works unauthenticated at low volume. A fine-grained token with no repository access raises limits.",
        env=[("GITHUB_ADVISORY_TOKEN", False, "Optional fine-grained token with no repository permissions, used only for rate limits.")],
        rate="GitHub REST limits: 60 requests an hour unauthenticated, 5,000 with a token.",
        cache="Advisory pages 6 hours in the plugin middleware.",
        terms="Advisory data is CC BY 4.0. Attribute the GitHub Advisory Database.",
        hosts=["api.github.com"],
        notes="Zero-build quick win for v0.1. Enable only the read-only `security_advisories` toolset (`get_global_security_advisory`, `list_global_security_advisories`), never repository, issue or pull request tools. Complements OSV for package-level answers and NVD for CVSS.",
        verified=f"`/advisories?per_page=1` returned 200 unauthenticated from the build box on 16 October 2026. `github/github-mcp-server` is public. {SECOND}, which read the toolset names in the server README.",
        config="""```yaml
mcp_servers:
  ghsa:
    command: "<PROFILE_HOME>/mcp/vendor/github-mcp-server/<pinned binary>"
    args: ["stdio", "--toolsets", "security_advisories", "--read-only"]   # confirm flag names in the pinned release
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_ADVISORY_TOKEN}"
    tools:
      include: ["get_global_security_advisory", "list_global_security_advisories"]
    enabled: true
    lazy: true
    timeout: 60
    trust: untrusted
```
Field names from """ + hsrc('website/docs/reference/mcp-config-reference.md') + ". The `tools.include` list is the backstop if a flag changes upstream.",
        files=["mcp/servers.yaml (entry `ghsa`, wrap)", "mcp/vendor/github-mcp-server.lock", "mcp/github-advisories/tests/test_ghsa_wrap.py", "mcp/github-advisories/SOURCE.md", "docs/connectors/github-advisories.md (generated)"],
        tools=[
            ("list_global_security_advisories", "Filter by ecosystem, affected package, severity, CVE or GHSA id (upstream tool).", obj({"ecosystem": {"type": S}, "affects": {"type": S}, "severity": {"enum": ["low", "medium", "high", "critical"]}, "cve_id": CVE})),
            ("get_global_security_advisory", "One advisory by GHSA id (upstream tool).", obj({"ghsaId": {"type": S, "pattern": "^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$"}}, ["ghsaId"])),
        ],
        fixtures=["advisories_page.json", "advisory_withdrawn.json", "tools_list.json (recorded tools/list)"],
        wrap=True,
        extra_tests=["Filter test: no tool outside the two advisory tools registers, even if the toolset flag is ignored."],
        extra_criteria=["The token, if set, has no repository permissions (documented, and doctor warns if the token can read a repository)."],
    ),
    dict(
        key="taxii-ctis", server="taxii", name="Generic TAXII 2.1 reader for ASD CTIS and other TAXII sources",
        group="Australian government", milestone=M_V02, priority="p2",
        docs="https://www.cyber.gov.au/become-a-partner",
        endpoints=[
            ("GET", "<api root>/collections/", "TAXII 2.1 collections the credentials can read. ASD issues the API root, collection id and credentials during CTIS onboarding"),
            ("GET", "<api root>/collections/{id}/objects/?added_after=...", "STIX 2.1 envelope, paged with `more` and `next`"),
        ],
        auth="HTTP Basic credentials issued to an ASD Network Partner during CTIS onboarding (membership-gated, under a confidentiality deed).",
        env=[("TAXII_API_ROOT", True, "API root URL issued at onboarding."), ("TAXII_COLLECTION_ID", True, "Collection id."), ("TAXII_USERNAME", True, "Username."), ("TAXII_PASSWORD", True, "Password.")],
        rate="Not published. Microsoft's onboarding guide for Sentinel suggests polling hourly for indicators at most a month old; use that as the ceiling.",
        cache="Objects go into the intel store. Collection list 24 hours.",
        terms="CTIS content is covered by the Network Partner deed. It must never appear in this public repository, fixtures, logs that are shared, or exports without a TLP check.",
        default_off="Membership-gated. Ships with `enabled: false` and no endpoint; the user adds their own onboarding details.",
        hosts=["(user supplied API root host, added to the allowlist by `doctor --add-host` with confirmation)"],
        notes="One read-only TAXII 2.1 client serves CTIS, other TAXII feeds and optionally MITRE's ATT&CK TAXII server. Contributing back to CTIS is out of scope. Onboarding: eligibility check, Network Partner form and deed, register interest in the partner portal, technical onboarding with the CTIS service desk. Pairs with Brolga (v1.0) as a context layer.",
        verified="cyber.gov.au partner pages could not be fetched by either inventory (site blocks automated clients); content seen through a search index and Microsoft's public `MSFT-AU-Security/SentinelCTIS` guide.",
        tools=[
            ("taxii_list_collections", "Collections the configured credentials can read.", obj({})),
            ("taxii_get_objects", "Page through STIX objects with `added_after` and type filters.", obj({"added_after": {"type": S, "format": "date-time"}, "types": {"type": "array", "items": {"type": S}}, "limit": LIMIT(100, 1000)})),
            ("taxii_lookup_indicator", "Find stored indicators matching an IP, domain, URL or hash.", obj({"value": {"type": S, "minLength": 3}}, ["value"])),
            ("taxii_sync_status", "Last sync time, object counts and errors per collection.", obj({})),
        ],
        fixtures=["discovery.json (synthetic)", "collections.json (synthetic)", "envelope_page1_more.json (synthetic)", "bundle_indicator_malware_relationship.json (synthetic)", "taxii_401.json", "indicator_expired.json (synthetic)"],
        extra_tests=["TLP test: objects marked TLP:AMBER or above are excluded from STIX export and briefings sent outside the profile unless the user overrides per run."],
        extra_criteria=["All fixtures are synthetic; a CI check fails on any fixture whose id matches a real CTIS collection format.", "No contribution or write call exists."],
    ),
    dict(
        key="ncsc-nz", server="ncscnz", name="NCSC NZ alerts (formerly CERT NZ)",
        group="Regional government", milestone=M_V02, priority="p2",
        docs="https://www.ncsc.govt.nz/alerts/",
        endpoints=[("GET", "https://www.ncsc.govt.nz/alerts/?start=N", "HTML alert list with pagination. No RSS found; cert.govt.nz redirects here")],
        auth="None.", env=[],
        rate="One list page per hour, item pages at most 1 every 5 seconds.",
        cache="List 1 hour, items 7 days.",
        terms="Licence not confirmed. Return title, date, link and extracted CVEs; quote short passages only.",
        hosts=["www.ncsc.govt.nz"],
        notes="Neighbour-country alerts often overlap ASD alerts and sometimes arrive earlier. HTML scraping is brittle, so the schema drift check covers the list selectors. Dedupe 'UPDATED:' alerts by URL.",
        verified=f"`/alerts/` returned 200 from the build box on 16 October 2026. {SECOND}, which found no RSS (several guessed feed paths returned 404).",
        tools=[
            ("ncscnz_list_alerts", "Recent alerts with title, date and link.", obj({"since": DATE, "limit": LIMIT(20, 100)})),
            ("ncscnz_get_alert", "One alert as cleaned text with extracted CVEs.", obj({"url": {"type": S, "format": "uri", "pattern": "^https://www\\.ncsc\\.govt\\.nz/"}}, ["url"])),
        ],
        fixtures=["alerts_page.html", "alert_updated_repeat.html", "alert_no_date.html"],
    ),
    dict(
        key="cloudflare-urlscanner", server="cfscan", name="Cloudflare URL Scanner (unlisted scans, approval-gated)",
        group="Internet and attack telemetry", milestone=M_V02, priority="p2",
        docs="https://developers.cloudflare.com/radar/investigate/url-scanner/",
        endpoints=[
            ("POST", "https://api.cloudflare.com/client/v4/accounts/{account_id}/urlscanner/v2/scan", "Submit a scan. Must send `visibility: Unlisted`"),
            ("GET", "https://api.cloudflare.com/client/v4/accounts/{account_id}/urlscanner/v2/result/{scan_id}", "Result; 404 until finished, poll every 10 to 30 seconds"),
        ],
        auth="Cloudflare API token with Account > URL Scanner > Edit.",
        env=[("CLOUDFLARE_URLSCAN_API_TOKEN", True, "Token scoped to URL Scanner only."), ("CLOUDFLARE_ACCOUNT_ID", True, "Account id for the scan endpoints.")],
        rate="Cloudflare client API limits apply. Bulk submit up to 100 URLs; this connector submits one at a time.",
        cache="Results kept in the intel store; Cloudflare keeps successful scans 12 months.",
        terms="Scans default to Public on Cloudflare's side and appear in the recent scans list, so an internal URL could be published. This connector always sends Unlisted.",
        default_off="Submitting a scan is a write to a third party. Ships with `enabled: false`, and every submit needs human approval.",
        hosts=["api.cloudflare.com"],
        notes="Thin first-party facade rather than the unified server, because the unified server would expose the submit endpoint without the Unlisted guarantee. Read tools can also be reached through the unified server under `*_accounts_urlscanner_*`, which Hermes's own catalog entry excludes by default.",
        verified=f"{SECOND}: docs, token permission, retention and visibility default read from Cloudflare's URL Scanner documentation.",
        tools=[
            ("urlscan_submit_unlisted", "Submit a URL with Unlisted visibility, after human approval.", obj({"url": URL, "approval_token": {"type": S}}, ["url", "approval_token"])),
            ("urlscan_get_result", "Poll and return verdict, final URL, IPs and ASNs.", obj({"scan_id": {"type": S}}, ["scan_id"])),
        ],
        fixtures=["submit_response.json", "result_404_in_progress.json", "result_malicious.json"],
        extra_tests=["Every submit request body in every cassette contains `\"visibility\": \"Unlisted\"` (asserted).", "Submit without a valid approval token is refused before any network call."],
        extra_criteria=["No code path can submit a Public scan."],
    ),
    dict(
        key="cve-program", server="cve", name="CVE Program records (CVE Services API and cvelistV5)",
        group="Vulnerability intelligence", milestone=M_V02, priority="p2",
        docs="https://www.cve.org/",
        endpoints=[("GET", "https://cveawg.mitre.org/api/cve/{CVE-ID}", "CNA record in CVE JSON 5.x"), ("GIT", "https://github.com/CVEProject/cvelistV5", "Bulk records, for the refresh workflow")],
        auth="None for reading.", env=[],
        rate="Not published. Self-imposed 1 request a second; bulk work uses the Git repository.",
        cache="Records 24 hours.",
        terms="Reproduction is allowed if copies keep MITRE's copyright designation and the licence. Keep the notice in `mcp/cve/SOURCE.md` and envelopes.",
        hosts=["cveawg.mitre.org"],
        notes="Fallback when NVD has not enriched a CVE yet: the CNA record often arrives first. Lives beside KEV, EPSS and NVD in the vulnerability priority tools.",
        verified=f"`/api/cve/CVE-2021-44228` returned 200 from the build box on 16 October 2026. `CVEProject/cvelistV5` is public. {SECOND}.",
        tools=[("cve_get_record", "The CNA record with description, affected products, references and state.", obj({"cve_id": CVE}, ["cve_id"]))],
        fixtures=["CVE-2021-44228.json", "rejected_record.json", "reserved_id_404.json"],
    ),
    dict(
        key="abuseipdb", server="abuseipdb", name="AbuseIPDB IP reputation",
        group="Global threat intelligence", milestone=M_V02, priority="p2",
        docs="https://docs.abuseipdb.com/",
        endpoints=[("GET", "https://api.abuseipdb.com/api/v2/check", "Confidence score and reports for an IP"), ("GET", "https://api.abuseipdb.com/api/v2/check-block", "Summary for a CIDR")],
        auth="`Key` header with a free or paid AbuseIPDB key.",
        env=[("ABUSEIPDB_API_KEY", True, "AbuseIPDB key.")],
        rate="Free Individual plan: 1,000 checks a day and 100 block checks a day.",
        cache="Checks 6 hours.",
        terms="Terms not confirmed by either inventory. Check before release.",
        hosts=["api.abuseipdb.com"],
        notes="Build two read tools on the shared client. An official `AbuseIPDB/AbuseIPDB-MCP` server exists; prefer the thin first-party tools so the report tool can never be exposed. Reporting an IP is out of scope here.",
        verified=f"`/api/v2/check` returned 401 without a key from the build box on 16 October 2026. {SECOND}.",
        tools=[
            ("abuseipdb_check_ip", "Confidence score, report count, ISP, usage type and country.", obj({"ip": IP, "max_age_days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 90}}, ["ip"])),
            ("abuseipdb_check_block", "Summary for a CIDR (at most /24 on the free plan).", obj({"network": {"type": S}}, ["network"])),
        ],
        fixtures=["check_ip.json", "check_block.json", "abuseipdb_401.json", "abuseipdb_429_daily.json"],
        extra_tests=["Private and reserved IPs are refused without a network call."],
    ),
    dict(
        key="spamhaus-drop", server="drop", name="Spamhaus DROP, DROPv6 and ASN-DROP",
        group="Global threat intelligence", milestone=M_V02, priority="p2",
        docs="https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
        endpoints=[("GET", "https://www.spamhaus.org/drop/drop_v4.json", "JSON lines: CIDR, SBL id, RIR"), ("GET", "https://www.spamhaus.org/drop/drop_v6.json", "IPv6"), ("GET", "https://www.spamhaus.org/drop/asndrop.json", "ASNs")],
        auth="None.", env=[],
        rate="Update once a day and never auto-fetch more than once an hour.",
        cache="24 hours on disk, loaded into an in-memory prefix tree.",
        terms="Provided free of charge; formal licence text not confirmed. Attribute Spamhaus.",
        hosts=["www.spamhaus.org"],
        notes="Very small. Answers 'is this IP or ASN run by criminals' offline once loaded.",
        verified=f"`drop_v4.json` returned 200 from the build box on 16 October 2026. {SECOND}.",
        tools=[
            ("drop_check_ip", "Whether an IP is inside a DROP netblock, with SBL id.", obj({"ip": IP}, ["ip"])),
            ("drop_check_asn", "Whether an ASN is on ASN-DROP.", obj({"asn": {"type": "integer", "minimum": 1}}, ["asn"])),
            ("drop_list_status", "Last fetch time and entry counts.", obj({})),
        ],
        fixtures=["drop_v4_head.json", "drop_v6_head.json", "asndrop_head.json"],
        extra_tests=["Fetch guard: a second fetch inside an hour is refused by the limiter."],
    ),
    dict(
        key="irap", server="irap", name="IRAP guidance",
        group="Australian government", milestone=M_V10, priority="p3",
        docs="https://www.cyber.gov.au/irap",
        endpoints=[("GET", "https://www.cyber.gov.au/irap", "IRAP overview"), ("GET", "https://www.cyber.gov.au/business-government/protecting-devices-systems/assessment-evaluation-programs/irap/irap-consumer-guide", "IRAP consumer guide")],
        auth="None.", env=[],
        rate="Fetched only by the regeneration workflow, weekly, 1 request every 5 seconds.",
        cache="Shipped snapshot with source sentence, URL, date and SHA-256 per item.",
        terms="Government content. Quote short passages with attribution.",
        hosts=["www.cyber.gov.au"],
        notes="Small snapshot-backed server built the same way as the AU obligations server (`aureg`). Inherits the cyber.gov.au fetch risk and fallback plan from the ACSC connector.",
        verified="Neither inventory could fetch cyber.gov.au directly on 16 October 2026; pages were seen through a search index and an earlier snapshot.",
        tools=[
            ("irap_search_guidance", "Search the IRAP pages in the snapshot.", obj({"query": {"type": S, "minLength": 2}}, ["query"])),
            ("irap_consumer_checklist", "The consumer guide's checks as a list, each linked to its source paragraph.", obj({})),
        ],
        fixtures=["irap_consumer_guide.html (snapshot)", "question_not_answered (expects an explicit 'not covered')"],
    ),
    dict(
        key="pspf", server="pspf", name="Protective Security Policy Framework (PSPF)",
        group="Australian government", milestone=M_V10, priority="p3",
        docs="https://www.protectivesecurity.gov.au/",
        endpoints=[("GET", "https://www.protectivesecurity.gov.au/publications-library/pspf-page-2026", "PSPF 2026 requirements"), ("GET", "https://www.protectivesecurity.gov.au/", "Directions and publications")],
        auth="None.", env=[],
        rate="Regeneration workflow only, weekly.",
        cache="Shipped snapshot.",
        terms="Licence not confirmed. Quote short passages with attribution.",
        hosts=["www.protectivesecurity.gov.au"],
        notes="Commonwealth requirements, directions and markings. Answers must cite the requirement, never invent one. The site dropped automated clients for both inventories, so this needs the same fetch fallback ladder as ASD.",
        verified="Could not fetch on 16 October 2026 (dropped connection, HTTP 500 to a fetch service); paths from an earlier snapshot.",
        tools=[
            ("pspf_search", "Search PSPF requirements and directions in the snapshot.", obj({"query": {"type": S, "minLength": 2}}, ["query"])),
            ("pspf_list_directions", "Protective security directions with dates and links.", obj({})),
        ],
        fixtures=["pspf_snapshot_two_directions.json"],
    ),
    dict(
        key="scamwatch", server="scamwatch", name="Scamwatch alerts",
        group="Australian government", milestone=M_V10, priority="p3",
        docs="https://www.scamwatch.gov.au/",
        endpoints=[("GET", "https://www.scamwatch.gov.au/", "Homepage alerts (HTML). Statistics are an embedded Power BI report, out of scope")],
        auth="None.", env=[],
        rate="One request per 6 hours.",
        cache="6 hours.",
        terms="Licence not confirmed.",
        hosts=["www.scamwatch.gov.au"],
        notes="Useful for phishing triage and awareness (for example ATO and myGov impersonation). The site returns 403 to plain clients, so a 403 must be reported as 'blocked', never as 'no alerts'.",
        verified=f"{SECOND}: a fetch service returned the page, curl got 403.",
        tools=[("scamwatch_list_alerts", "Current scam alerts with title, date and link.", obj({"limit": LIMIT(10, 50)})), ("scamwatch_get_alert", "One alert as cleaned text.", obj({"url": {"type": S, "format": "uri", "pattern": "^https://www\\.scamwatch\\.gov\\.au/"}}, ["url"]))],
        fixtures=["homepage_three_alerts.html", "scamwatch_403.html"],
    ),
    dict(
        key="datagov-au", server="datagov", name="data.gov.au (CKAN)",
        group="Australian government", milestone=M_V10, priority="p3",
        docs="https://data.gov.au/",
        endpoints=[("GET", "https://data.gov.au/data/api/3/action/package_search", "CKAN search"), ("GET", "https://data.gov.au/data/api/3/action/package_show", "One package")],
        auth="None.", env=[],
        rate="One request a second.",
        cache="24 hours.",
        terms="Per dataset, in each record's `license_id`. Datasets with no licence are flagged.",
        hosts=["data.gov.au"],
        notes="Low direct threat value; context and sector data. A generic CKAN client is enough.",
        verified=f"`status_show` returned 200 from the build box on 16 October 2026. {SECOND}.",
        tools=[("datagov_search", "Packages with title, publisher, licence and resource links.", obj({"query": {"type": S, "minLength": 2}, "limit": LIMIT(10, 50)}, ["query"])), ("datagov_get_package", "One package with its resources.", obj({"id": {"type": S}}, ["id"]))],
        fixtures=["package_search.json", "package_notspecified_licence.json"],
    ),
    dict(
        key="auscert-member", server="auscertm", name="AusCERT member URL feed (AusMISP goes through the MISP connector)",
        group="Australian community", milestone=M_V10, priority="p3",
        docs="https://auscert.org.au/services/threat-intelligence/",
        endpoints=[("GET", "(member URL feed, format to confirm with a member)", "Malicious URL Feed"), ("MISP", "AusMISP", "Use the MISP connector")],
        auth="Paid AusCERT membership.",
        env=[("AUSCERT_URL_FEED", True, "Member feed URL, supplied by the user."), ("AUSCERT_FEED_TOKEN", False, "Credential if the feed needs one.")],
        rate="Per member terms; default hourly.",
        cache="1 hour.",
        terms="Member terms. Member data never enters this repository or fixtures.",
        default_off="Paid membership. Ships with `enabled: false`; the user supplies their own feed details.",
        hosts=["(user supplied)"],
        notes="Do not build until a member confirms the feed format. AusMISP is reached through the MISP connector, not here.",
        verified=f"{SECOND}: membership and service pages read; feed format not public.",
        tools=[("auscert_url_feed_lookup", "Check a URL or domain against the cached member URL feed.", obj({"value": {"type": S, "minLength": 3}}, ["value"])), ("auscert_url_feed_status", "Last fetch time and entry count.", obj({}))],
        fixtures=["url_feed_synthetic.txt (synthetic)"],
    ),
    dict(
        key="asd-blueprint", server="blueprint", name="ASD Blueprint for Secure Cloud",
        group="Australian government", milestone=M_V10, priority="p3",
        docs="https://blueprint.asd.gov.au/",
        endpoints=[("GET", "https://blueprint.asd.gov.au/<page>", "HTML reference designs and configuration guidance")],
        auth="None.", env=[],
        rate="Regeneration workflow only, weekly, 1 request every 5 seconds.",
        cache="Shipped snapshot.",
        terms="Licence not confirmed.",
        hosts=["blueprint.asd.gov.au"],
        notes="Microsoft 365 and cloud configuration guidance. Pairs with the M365-Secure integration.",
        verified=f"Homepage returned 200 from the build box on 16 October 2026. {SECOND}.",
        tools=[("blueprint_search", "Find the relevant Blueprint setting and return it with its link.", obj({"query": {"type": S, "minLength": 2}}, ["query"]))],
        fixtures=["blueprint_two_pages.json (snapshot)"],
    ),
    dict(
        key="phishtank", server="phish", name="PhishTank verified phishing URLs",
        group="Global threat intelligence", milestone=M_V10, priority="p3",
        docs="https://phishtank.org/developer_info.php",
        endpoints=[("GET", "https://data.phishtank.com/data/<app key>/online-valid.json", "Hourly database download (confirm path on the developer page)")],
        auth="Free application key for automated downloads; a descriptive `User-Agent` is required.",
        env=[("PHISHTANK_APP_KEY", False, "Application key. Without it, only a few downloads a day.")],
        rate="Hourly at most.",
        cache="1 hour.",
        terms="Licence not confirmed.",
        hosts=["data.phishtank.com", "cdn.phishtank.com"],
        notes="Shares the `phish` server with OpenPhish and the URLhaus cache for one combined phishing check.",
        verified=f"Developer page returned 200 from the build box on 16 October 2026. {SECOND}.",
        tools=[("phishtank_check_url", "Whether a URL is in the cached verified-online set.", obj({"url": URL}, ["url"]))],
        fixtures=["online_valid_five.json (synthetic)", "trailing_slash_variant"],
    ),
    dict(
        key="openphish", server="phish", name="OpenPhish community feed",
        group="Global threat intelligence", milestone=M_V10, priority="p3",
        docs="https://openphish.com/",
        endpoints=[("GET", "https://openphish.com/feed.txt", "Plain text, one URL per line (answered with a redirect from the build box; follow it within the allowlist)")],
        auth="None.", env=[],
        rate="Hourly at most.",
        cache="1 hour; an empty feed never wipes the cache.",
        terms="Licence not confirmed. The community feed is a small sample.",
        hosts=["openphish.com", "raw.githubusercontent.com"],
        notes="Adds `phish_check_url`, which checks OpenPhish, PhishTank and URLhaus caches together.",
        verified=f"`feed.txt` returned a 302 from the build box on 16 October 2026. {SECOND}, which read 200 with a short feed.",
        tools=[("phish_check_url", "Check a URL against the OpenPhish, PhishTank and URLhaus caches together.", obj({"url": URL}, ["url"]))],
        fixtures=["feed_three_lines.txt", "feed_empty.txt"],
    ),
    dict(
        key="misp", server="misp", name="MISP via the official MISP MCP server, for your own instance or AusMISP",
        group="CTI platforms", milestone=M_V10, priority="p3",
        docs="https://www.misp-project.org/",
        endpoints=[("MCP", "https://github.com/MISP/misp-mcp", "Official MISP MCP server; pin a commit"), ("REST", "<your MISP instance>", "Underlying API")],
        auth="The instance's API key, ideally a read-only key.",
        env=[("MISP_URL", True, "Instance URL."), ("MISP_API_KEY", True, "Read-only API key.")],
        rate="Per instance.",
        cache="None beyond the intel store.",
        terms="MISP software is AGPL-3.0; feed terms vary per feed. Respect TLP and sharing groups.",
        default_off="Needs the user's own instance. Ships with `enabled: false`.",
        hosts=["(user supplied)"],
        notes="Read-only first: search attributes, get an event, recent events. AusCERT members reach AusMISP through this connector. The upstream repository showed no detected licence; confirm before vendoring.",
        verified=f"`MISP/misp-mcp` is public. {SECOND}.",
        tools=[("(wrapped tools)", "Search attributes, get one event with galaxies, recent events. Write tools excluded by `tools.include`.", None)],
        fixtures=["event_three_attributes.json (synthetic)", "search_no_hits.json", "write_403.json"],
        wrap=True,
        config="""```yaml
mcp_servers:
  misp:
    command: "<PROFILE_HOME>/mcp/vendor/misp-mcp/<pinned launcher>"
    env:
      MISP_URL: "${MISP_URL}"
      MISP_API_KEY: "${MISP_API_KEY}"
    tools:
      include: ["<read tools frozen at build time>"]
    enabled: false
    lazy: true
    trust: untrusted
```""",
    ),
    dict(
        key="opencti", server="opencti", name="OpenCTI (your own instance)",
        group="CTI platforms", milestone=M_V10, priority="p3",
        docs="https://docs.opencti.io/",
        endpoints=[("GRAPHQL", "<your OpenCTI instance>/graphql", "Underlying API"), ("MCP", "https://github.com/FiligranHQ/xtm-mcp", "Vendor MCP server; licence to confirm")],
        auth="The instance's API token.",
        env=[("OPENCTI_URL", True, "Instance URL."), ("OPENCTI_TOKEN", True, "API token for a read-only user.")],
        rate="Per instance.",
        cache="None beyond the intel store.",
        terms="Community Edition Apache-2.0; Enterprise Edition has its own licence.",
        default_off="Needs the user's own instance. Ships with `enabled: false`.",
        hosts=["(user supplied)"],
        notes="Wrap the vendor server once its licence is clear; until then build the two read tools on the shared client. Brolga (v1.0) is an alternative read-only context layer over OpenCTI.",
        verified=f"`FiligranHQ/xtm-mcp` is public. {SECOND}.",
        tools=[("opencti_search_entities", "Actors, malware, indicators and reports.", obj({"query": {"type": S, "minLength": 2}, "types": {"type": "array", "items": {"type": S}}}, ["query"])), ("opencti_get_indicator_context", "Relationships and sightings for an indicator.", obj({"value": {"type": S}}, ["value"]))],
        fixtures=["indicator_graphql.json (synthetic)", "paginated.json (synthetic)", "expired_token.json"],
    ),
    dict(
        key="custom-feeds", server="custom_feeds", name="Custom RSS and Atom feeds and watch packs",
        group="Watches", milestone=M_V01, priority="p1",
        docs="docs/intel/watchlists.md",
        endpoints=[
            ("GET", "https://api.msrc.microsoft.com/update-guide/rss", "MSRC Security Update Guide, in the microsoft-security pack"),
            ("GET", "https://www.microsoft.com/en-us/security/blog/feed/ , /releasecommunications/api/v2/azure/rss , /releasecommunications/api/v1/m365/rss", "Microsoft Security blog, Azure updates and Microsoft 365 roadmap, in the microsoft-security pack"),
            ("GET", "https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id={board}", "Sentinel, Defender XDR, Defender for Endpoint and Defender for Cloud blogs, in the microsoft-security pack"),
            ("GET", "Any https feed URL the user lists under `feeds` in watchlists.yaml", "User feeds"),
        ],
        auth="None. Every feed is public.",
        env=[],
        rate="One request a second per feed, cached for an hour.",
        cache="Shared HTTP cache, one hour TTL. Offline mode and failed fetches serve a cached copy marked stale.",
        terms="Each feed's publisher terms. The shipped microsoft-security pack is Microsoft content under the Microsoft Terms of Use.",
        hosts=["api.msrc.microsoft.com", "www.microsoft.com", "techcommunity.microsoft.com"],
        notes="Generic RSS 2.0 and Atom reader for watches. Feeds come from shipped packs (`mcp/custom-feeds/packs/*.yaml`) and the user's own `feeds` list in watchlists.yaml. The allowlist covers the shipped packs; a user feed adds its own host at run time, https and DNS names only. `refresh --sources custom --store` loads items into the intel store as advisories, and the nightly watchlist run evaluates `watches` over them.",
        verified="Every microsoft-security pack URL answered 200 with RSS on 20 October 2026.",
        files=["mcp/custom-feeds/src/cyberau_custom_feeds/source.py", "mcp/custom-feeds/src/cyberau_custom_feeds/config.py", "mcp/custom-feeds/packs/microsoft-security.yaml", "mcp/custom-feeds/tests/test_custom_feeds.py", "mcp/custom-feeds/SOURCE.md"],
        tools=[
            ("custom_feed_list", "The custom feeds, packs and watches turned on in watchlists.yaml.", None),
            ("custom_feed_items", "Recent items from one configured feed, by feed id.", None),
        ],
        fixtures=["custom_feed_items_rss.xml", "custom_feed_items_atom.xml", "custom_feed_items_dtd.xml"],
        extra_criteria=["A feed URL must be https with a DNS host name. Every connection still goes through the private address floor."],
    ),
]
