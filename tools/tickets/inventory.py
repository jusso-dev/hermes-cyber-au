"""Connector inventory. Single source of truth for the README table, docs/research/connectors.md
and the connector tickets. Each entry was checked on 16 October 2026 (see `verified`)."""
from __future__ import annotations

from common import M_V01, M_V02, M_V10, hsrc

S = "string"


def obj(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "additionalProperties": False, "properties": props, "required": required or []}


CVE = {"type": S, "pattern": "^CVE-\\d{4}-\\d{4,}$"}
CVES = {"type": "array", "items": CVE, "minItems": 1, "maxItems": 100}
DATE = {"type": S, "format": "date", "description": "YYYY-MM-DD, interpreted in Australia/Sydney"}
LIMIT = lambda d, m: {"type": "integer", "minimum": 1, "maximum": m, "default": d}
IP = {"type": S, "description": "IPv4 or IPv6 address", "format": "ip"}

CONNECTORS = [
    dict(
        key="asd-acsc", server="asd", name="ASD's ACSC alerts, advisories and publications",
        group="Australian government", milestone=M_V01, priority="p0",
        docs="https://www.cyber.gov.au/",
        endpoints=[
            ("GET", "https://www.cyber.gov.au/rss/alerts", "RSS 2.0, rolling window of current alerts"),
            ("GET", "https://www.cyber.gov.au/rss/advisories", "RSS 2.0, rolling window of advisories"),
            ("GET", "https://www.cyber.gov.au/rss/publications", "RSS 2.0"),
            ("GET", "https://www.cyber.gov.au/rss/threats", "RSS 2.0"),
            ("GET", "https://www.cyber.gov.au/rss/news", "RSS 2.0 (one directory lists news at /acsc/view-all-content/news/rss; verify which is current)"),
            ("GET", "https://www.cyber.gov.au/<item path>", "HTML item page, fetched only for links that came from the feeds"),
        ],
        auth="None.", env=[],
        rate="No published limit. Self-imposed: one request per feed per 10 minutes, item pages at most 1 request every 5 seconds. The CDN is known to stall some egress paths, so use a 60 second timeout, 3 retries with backoff and fall back to the last good snapshot.",
        cache="Feeds: 15 minutes, honour ETag and Last-Modified. Item pages: 7 days keyed by URL and content hash.",
        terms="Check the cyber.gov.au copyright page for the current licence and attribution wording before shipping snapshots. Keep the attribution string in `mcp/asd/SOURCE.md`.",
        hosts=["www.cyber.gov.au"],
        notes="The feeds are rolling windows, so items drop out. Every poll must persist each item to the intel store (`advisories` table) or it is lost. Map each item to a stable id `asd:<feed>:<sha1(link)>`.",
        verified="`/rss/alerts`, `/rss/advisories`, `/rss/publications`, `/rss/threats` listed by two independent feed directories. Direct fetch from the build box timed out, which matches the CDN note above.",
        tools=[
            ("asd_list_items", "List items from one or more ASD feeds, newest first.", obj({
                "feeds": {"type": "array", "items": {"enum": ["alerts", "advisories", "publications", "threats", "news"]}, "default": ["alerts", "advisories"]},
                "since": DATE, "limit": LIMIT(20, 100)})),
            ("asd_get_item", "Fetch one ASD item page and return cleaned text, headings, CVE ids, ATT&CK ids and links.", obj({
                "url": {"type": S, "format": "uri", "pattern": "^https://www\\.cyber\\.gov\\.au/"}}, ["url"])),
            ("asd_search", "Search stored ASD items (intel store full text index) by keyword, CVE or vendor.", obj({
                "query": {"type": S, "minLength": 2}, "since": DATE, "limit": LIMIT(10, 50)}, ["query"])),
        ],
        fixtures=["rss_alerts.xml", "rss_advisories.xml", "rss_empty.xml", "rss_malformed.xml", "item_advisory.html", "timeout (simulated)", "http_500.txt", "connection_reset (simulated)"],
        extra_tests=[
            "Runtime fetch check (manual, recorded in the PR): from a real Hermes install (the installer on Linux or macOS, and the `nousresearch/hermes-agent` Docker image), run `cyberau-mcp health asd --live --verbose` and record, per feed URL: HTTP version used, status, bytes, elapsed time and whether a `User-Agent` and `Accept` header set was needed. Two independent research passes on 16 October 2026 could not fetch cyber.gov.au from build hosts (a timeout, a dropped HTTP/2 connection and an HTTP 500 from a fetch service), so this step must run on the real runtime, not CI only.",
            "Fallback ladder test: with the direct fetch forced to fail, the client tries (1) HTTP/1.1 with a full, honest browser-like header set that still names the project in `User-Agent`, then (2) the last good snapshot from the intel store, and returns `cache: stale` with `data_as_of` and a warning naming the failed feed. It never returns an empty list as if there were no alerts.",
        ],
        extra_criteria=[
            "The runtime fetch check above has been run from a real Hermes runtime (installer and Docker), and its results are written to `mcp/asd/SOURCE.md` with the date.",
            "If the direct fetch still fails from the runtime, the fallback plan is in place before v0.1 ships: HTTP/1.1 retry with full headers, then last good snapshot with a staleness flag, plus a documented manual path (the user downloads the RSS in a browser and runs `cyberau-mcp import asd <file>`). `asd_feed_status` reports which rung of the ladder served the answer.",
            "Items that drop out of the rolling feed between polls are still answerable from the intel store.",
        ],
        extra_tools=[
            ("asd_feed_status", "Last successful fetch, fetch method used (direct, HTTP/1.1 retry, snapshot, manual import), item counts and staleness per feed.", obj({"feeds": {"type": "array", "items": {"enum": ["alerts", "advisories", "publications", "threats", "news"]}}})),
        ],
    ),
    dict(
        key="asd-ism", server="ism", name="Information Security Manual (ISM) OSCAL catalogue",
        group="Australian government", milestone=M_V01, priority="p0",
        docs="https://github.com/AustralianCyberSecurityCentre/ism-oscal",
        endpoints=[
            ("GET", "https://api.github.com/repos/AustralianCyberSecurityCentre/ism-oscal/releases", "Release list. Latest seen: `v2026.09.4` (3 September 2026)"),
            ("GET", "https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal/<tag>/ISM_catalog.json", "OSCAL catalog"),
            ("GET", "https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal/<tag>/ISM_<BASELINE>-baseline-resolved-profile_catalog.json", "Resolved baselines: NON_CLASSIFIED, OFFICIAL_SENSITIVE, PROTECTED, SECRET, TOP_SECRET, E8_ML1, E8_ML2, E8_ML3"),
        ],
        auth="None. Optional `GITHUB_TOKEN` raises the GitHub API limit from 60 to 5,000 requests an hour.",
        env=[("GITHUB_TOKEN", False, "Optional. Read-only token for the GitHub releases API.")],
        rate="GitHub API: 60 requests an hour unauthenticated. Raw downloads happen once per release.",
        cache="Snapshot per release tag under `mcp/ism/data/<tag>/` (shipped, regenerated by the skill data workflow). Release list cached 12 hours.",
        terms="ISM content is published by ASD. Record the release tag, file SHA-256 and retrieval date for every answer.",
        hosts=["api.github.com", "raw.githubusercontent.com"],
        notes="Keep at least the two most recent releases so a question about a past date uses the release in force then. Control ids are normalised so `ISM-1173`, `1173` and the OSCAL id all resolve (check the exact OSCAL id format in `ISM_catalog.json` before writing the normaliser).",
        verified="Repository is public, files listed via the GitHub contents API, releases `v2026.03.24`, `v2026.06.18`, `v2026.09.4` present.",
        tools=[
            ("ism_get_control", "Return one ISM control with statement, applicability, guideline and section, release tag and source hash.", obj({
                "control_id": {"type": S, "pattern": "^(ISM-)?\\d{3,4}$|^ism-"}, "release": {"type": S, "description": "Release tag. Default: latest in snapshot"}}, ["control_id"])),
            ("ism_search", "Full text search across controls, optionally limited to a baseline.", obj({
                "query": {"type": S, "minLength": 2},
                "baseline": {"enum": ["NON_CLASSIFIED", "OFFICIAL_SENSITIVE", "PROTECTED", "SECRET", "TOP_SECRET", "E8_ML1", "E8_ML2", "E8_ML3"]},
                "release": {"type": S}, "limit": LIMIT(10, 50)}, ["query"])),
            ("ism_list_baseline", "List control ids in a baseline for a release.", obj({
                "baseline": {"enum": ["NON_CLASSIFIED", "OFFICIAL_SENSITIVE", "PROTECTED", "SECRET", "TOP_SECRET", "E8_ML1", "E8_ML2", "E8_ML3"]},
                "release": {"type": S}}, ["baseline"])),
            ("ism_diff", "Controls added, removed or changed between two releases.", obj({
                "from_release": {"type": S}, "to_release": {"type": S}}, ["from_release", "to_release"])),
        ],
        fixtures=["releases.json", "ISM_catalog.min.json (trimmed to 20 controls)", "E8_ML1 resolved profile (trimmed)", "github_403_rate_limited.json"],
    ),
    dict(
        key="asd-essentials", server="e8", name="Essential Eight and ASD Essentials",
        group="Australian government", milestone=M_V01, priority="p0",
        docs="https://www.cyber.gov.au/publication/what-is-the-essentials",
        endpoints=[
            ("GET", "ISM OSCAL `ISM_E8_ML1/2/3-baseline-resolved-profile_catalog.json`", "Machine-readable Essential Eight maturity level baselines mapped to ISM controls"),
            ("GET", "https://www.cyber.gov.au/publication/what-is-the-essentials", "ASD Essentials model: principles, actions, domains"),
            ("GET", "https://www.cyber.gov.au/publication/essentials-for-enterprise-it", "Chapter: enterprise IT (evolution of the Essential Eight), eight domains in priority phases"),
            ("GET", "https://www.cyber.gov.au/publication/essentials-for-cloud", "Chapter: SaaS and PaaS environments"),
            ("GET", "https://www.asd.gov.au/news/2026-10-15-asd-essentials-evolving-our-approach-cyber-security-resilience", "Launch notice, 15 October 2026. Also names an OT chapter and transition guidance"),
        ],
        auth="None.", env=[],
        rate="Pages fetched only by the regeneration workflow, at most once a day, 1 request every 5 seconds.",
        cache="Shipped JSON snapshot `mcp/e8/data/essentials-<date>.json` and `mcp/e8/data/e8-maturity-<ism-release>.json`, each with source URL, retrieval date and SHA-256 of the source page.",
        terms="ASD content. Same attribution handling as the ASD connector.",
        hosts=["www.cyber.gov.au", "www.asd.gov.au", "raw.githubusercontent.com"],
        notes="ASD launched the Essentials on 15 October 2026 and keeps the Essential Eight during a transition period. Support both. Essentials uses priority phases, not maturity levels, so the tool output must never present a phase as a maturity score. The OT chapter and the transition guide URLs must be confirmed on cyber.gov.au before the parser is written.",
        verified="Launch notice and the enterprise IT and cloud chapter pages found on 16 October 2026. E8 ML baselines present in ISM OSCAL.",
        tools=[
            ("e8_requirements", "Requirements for one Essential Eight mitigation strategy at a maturity level, with the mapped ISM control ids.", obj({
                "strategy": {"enum": ["patch_applications", "patch_operating_systems", "multi_factor_authentication", "restrict_admin_privileges", "application_control", "restrict_office_macros", "user_application_hardening", "regular_backups"]},
                "maturity_level": {"type": "integer", "minimum": 1, "maximum": 3}}, ["strategy", "maturity_level"])),
            ("essentials_chapter", "Domains, principles, actions and priority phases for one ASD Essentials chapter.", obj({
                "chapter": {"enum": ["enterprise-it", "cloud", "ot"]}, "domain": {"type": S}}, ["chapter"])),
            ("essentials_transition", "How an Essential Eight strategy maps into the Essentials domains, quoted from ASD's transition guidance only.", obj({
                "strategy": {"type": S}}, ["strategy"])),
        ],
        fixtures=["essentials_enterprise_it.html", "essentials_cloud.html", "E8_ML2 resolved profile (trimmed)", "page_layout_changed.html (drift case)"],
    ),
    dict(
        key="cisa-kev", server="kev", name="CISA Known Exploited Vulnerabilities",
        group="Vulnerability intelligence", milestone=M_V01, priority="p0",
        docs="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        endpoints=[("GET", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "Full catalogue, JSON")],
        auth="None.", env=[],
        rate="One full download per 6 hours. Conditional GET with ETag.",
        cache="Whole catalogue in the HTTP cache (6 hours) and normalised into the intel store `vulnerabilities` table.",
        terms="US Government work. Cite CISA and the `dateAdded` field.",
        hosts=["www.cisa.gov"],
        notes="Fields used: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `notes`, `cwes`. Validate the download against the published JSON schema before use.",
        verified="JSON feed returned HTTP 200 on 16 October 2026.",
        tools=[
            ("kev_lookup", "Check whether CVEs are in KEV and return their entries.", obj({"cve_ids": CVES}, ["cve_ids"])),
            ("kev_recent", "Entries added in the last N days, optionally filtered by vendor.", obj({
                "days": {"type": "integer", "minimum": 1, "maximum": 90, "default": 7}, "vendor": {"type": S}, "ransomware_only": {"type": "boolean", "default": False}})),
            ("kev_search", "Search by vendor, product or keyword.", obj({"query": {"type": S, "minLength": 2}, "limit": LIMIT(20, 200)}, ["query"])),
        ],
        fixtures=["kev_full_trimmed.json (50 entries)", "kev_304_not_modified", "kev_schema_violation.json"],
    ),
    dict(
        key="first-epss", server="epss", name="FIRST EPSS",
        group="Vulnerability intelligence", milestone=M_V01, priority="p0",
        docs="https://api.first.org/epss/",
        endpoints=[
            ("GET", "https://api.first.org/data/v1/epss?cve=<comma list>", "Scores and percentiles. Also `date`, `scope=time-series`, `epss-gt`, `percentile-gt`, `limit`, `offset`"),
            ("GET", "Daily bulk CSV linked from https://www.first.org/epss/data", "Full daily file. Resolve the current URL from that page; do not hard-code a redirect target"),
        ],
        auth="None.", env=[],
        rate="1,000 requests a minute for the public API (HTTP 429 above that). Batch up to 100 CVEs per call. Use the bulk CSV for anything over 1,000 CVEs.",
        cache="Scores change daily: cache 12 hours, keyed by CVE set and date. Store daily score history in the intel store.",
        terms="FIRST EPSS terms of use. Cite model version and score date from the response.",
        hosts=["api.first.org", "www.first.org", "epss.empiricalsecurity.com"],
        notes="Return `epss`, `percentile`, `date` and the model version string from the response envelope.",
        verified="`/data/v1/epss?cve=CVE-2024-3400` returned HTTP 200 on 16 October 2026.",
        tools=[
            ("epss_scores", "EPSS score and percentile for up to 100 CVEs.", obj({"cve_ids": CVES, "date": DATE}, ["cve_ids"])),
            ("epss_history", "Score history for one CVE over the last 30 days.", obj({"cve_id": CVE}, ["cve_id"])),
            ("epss_top", "Highest scoring CVEs today above a threshold.", obj({"min_epss": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.5}, "limit": LIMIT(50, 500)})),
        ],
        fixtures=["epss_batch.json", "epss_timeseries.json", "epss_429.json", "epss_unknown_cve.json"],
    ),
    dict(
        key="nvd", server="nvd", name="NIST National Vulnerability Database",
        group="Vulnerability intelligence", milestone=M_V01, priority="p0",
        docs="https://nvd.nist.gov/developers/vulnerabilities",
        endpoints=[
            ("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0", "CVE API 2.0: `cveId`, `keywordSearch`, `cpeName`, `pubStartDate`/`pubEndDate`, `lastModStartDate`/`lastModEndDate`, `hasKev`, `cvssV3Severity`, `resultsPerPage` (max 2,000), `startIndex`"),
            ("GET", "https://services.nvd.nist.gov/rest/json/cvehistory/2.0", "Change history"),
        ],
        auth="Optional API key in the `apiKey` request header.",
        env=[("NVD_API_KEY", False, "Optional. Raises the limit from 5 to 50 requests per rolling 30 seconds.")],
        rate="5 requests per rolling 30 seconds without a key, 50 with a key. NVD asks clients to sleep about 6 seconds between requests. The limiter must enforce the rolling window, not a fixed one.",
        cache="CVE records: 24 hours. Searches: 1 hour. Persist CVSS and CWE to the intel store.",
        terms="Show the NVD notice: \"This product uses data from the NVD API but is not endorsed or certified by the NVD.\"",
        hosts=["services.nvd.nist.gov"],
        notes="Expect slow responses and 503s. Time out at 60 seconds and degrade to cached data with a warning.",
        verified="CVE API returned HTTP 200 without a key on 16 October 2026. Limits from NVD's developer start page.",
        tools=[
            ("nvd_get_cve", "One CVE: descriptions, CVSS v3.1 and v4.0 metrics, CWEs, references, configurations summary.", obj({"cve_id": CVE}, ["cve_id"])),
            ("nvd_search", "Search CVEs with NVD filters.", obj({
                "keyword": {"type": S}, "cpe_name": {"type": S}, "published_from": DATE, "published_to": DATE,
                "kev_only": {"type": "boolean", "default": False}, "cvss_v3_severity": {"enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                "limit": LIMIT(20, 200)})),
            ("nvd_cve_history", "Change history for one CVE.", obj({"cve_id": CVE}, ["cve_id"])),
        ],
        fixtures=["cve_CVE-2024-3400.json", "search_keyword_page1.json", "search_keyword_page2.json", "nvd_403_rate_limited", "nvd_503"],
    ),
    dict(
        key="osv", server="osv", name="OSV.dev open source vulnerabilities",
        group="Vulnerability intelligence", milestone=M_V02, priority="p2",
        docs="https://google.github.io/osv.dev/api/",
        endpoints=[
            ("POST", "https://api.osv.dev/v1/query", "Query by package and version, or commit"),
            ("POST", "https://api.osv.dev/v1/querybatch", "Batch queries"),
            ("GET", "https://api.osv.dev/v1/vulns/<id>", "One record (GHSA, PYSEC, GO and others)"),
        ],
        auth="None.", env=[],
        rate="No key. Self-imposed 10 requests a second. Use querybatch for lists.",
        cache="Records 24 hours. Query results 6 hours.",
        terms="OSV data is aggregated from many databases; keep each record's `database_specific` source and licence fields.",
        hosts=["api.osv.dev"],
        notes="Useful for SBOM-driven prioritisation alongside KEV and EPSS.",
        verified="`/v1/vulns/GHSA-jfh8-c2jp-5v3q` returned the Log4j record on 16 October 2026.",
        tools=[
            ("osv_query", "Vulnerabilities affecting a package version.", obj({"ecosystem": {"type": S}, "package": {"type": S}, "version": {"type": S}}, ["ecosystem", "package"])),
            ("osv_get", "One OSV record by id.", obj({"id": {"type": S}}, ["id"])),
            ("osv_batch", "Up to 100 package queries in one call.", obj({"queries": {"type": "array", "maxItems": 100, "items": {"type": "object"}}}, ["queries"])),
        ],
        fixtures=["query_pypi_jinja2.json", "vuln_GHSA.json", "batch.json"],
    ),
    dict(
        key="cloudflare-radar", server="cloudflare_radar", name="Cloudflare Radar via Cloudflare's unified MCP server",
        group="Internet and attack telemetry", milestone=M_V01, priority="p1",
        docs="https://developers.cloudflare.com/radar/",
        endpoints=[
            ("MCP", "https://mcp.cloudflare.com/mcp?codemode=false", "Cloudflare's unified remote MCP server (github.com/cloudflare/mcp). With `codemode=false` each API endpoint is its own tool; Radar endpoints match `*_radar_*`"),
            ("GET", "https://api.cloudflare.com/client/v4/radar/annotations/outages", "Underlying Radar API: outages, filter `location=AU`"),
            ("GET", "https://api.cloudflare.com/client/v4/radar/attacks/layer7/summary", "Underlying Radar API: application layer attack summaries"),
            ("GET", "https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events , /radar/bgp/leaks/events", "Underlying Radar API: BGP events"),
            ("GET", "https://api.cloudflare.com/client/v4/radar/ranking/top", "Underlying Radar API: domain rankings"),
        ],
        auth="OAuth 2.1 through Hermes's MCP client (scope the grant to Radar read), or a custom API token with Account > Radar > Read sent as a bearer header.",
        env=[("CLOUDFLARE_RADAR_API_TOKEN", False, "Optional. Custom API token with only Account > Radar > Read. Without it, Hermes uses OAuth on first connect.")],
        rate="Cloudflare client API: 1,200 requests per 5 minutes per token; going over blocks calls for 5 minutes. Read `retry-after`.",
        cache="No local cache in the wrapped server. The `radar-au` skill keeps its own call budget and the briefing routine stores summaries in the intel store.",
        terms="Cloudflare Radar API data is CC BY-NC 4.0: non-commercial use only unless you have an agreement with Cloudflare. Attribute Cloudflare Radar in every briefing that uses it.",
        default_off="Radar data is CC BY-NC 4.0 (see Terms). The server ships with `enabled: false` and users bring their own Cloudflare token or OAuth grant.",
        hosts=["mcp.cloudflare.com"],
        notes="Retargeted from a first-party Radar connector to a wrap of Cloudflare's unified MCP server. Cloudflare's older dedicated Radar MCP server (`cloudflare/mcp-server-cloudflare`, `apps/radar`) is marked deprecated in its README in favour of the unified server, so nothing here builds on it. Hermes ships a catalog entry for the unified server (" + hsrc('optional-mcps/cloudflare/manifest.yaml') + "), but that entry excludes `*_radar_*` by default and exposes about 1,900 account tools, so this distribution adds its own narrow server entry instead: Radar tools only, read only. `tools.include` accepts fnmatch globs (" + hsrc('website/docs/reference/mcp-config-reference.md') + "), and include wins over exclude.",
        verified="`https://mcp.cloudflare.com/mcp` answered 401 without auth on 16 October 2026 (exists). Hermes manifest read at the pinned commit. Radar REST endpoint returned the expected missing-auth error. Deprecation of the dedicated Radar server per its README, checked by a second inventory on the same date.",
        config="""```yaml
mcp_servers:
  cloudflare_radar:
    url: "https://mcp.cloudflare.com/mcp?codemode=false"
    # Either OAuth (default) ...
    auth: oauth
    # ... or, when CLOUDFLARE_RADAR_API_TOKEN is set, bootstrap renders this instead of `auth`:
    # headers:
    #   Authorization: "Bearer ${CLOUDFLARE_RADAR_API_TOKEN}"
    tools:
      include: ["*_radar_*"]
    enabled: false        # non-commercial data terms; the user switches it on
    lazy: true
    timeout: 120
    trust: untrusted
```
Field names from """ + hsrc('website/docs/reference/mcp-config-reference.md') + """ (`url`, `headers`, `auth: oauth`, `enabled`, `tools.include`). Confirm at build time that the unified server accepts a bearer API token as well as OAuth; if it does not, drop the token path and keep OAuth only.""",
        files=["mcp/servers.yaml (entry `cloudflare_radar`, wrap, no local code)", "skills/radar-au/SKILL.md (AU-focused question patterns, call budget, attribution)", "mcp/cloudflare-radar/tests/test_radar_wrap.py (config render and tool filter tests)", "mcp/cloudflare-radar/SOURCE.md", "docs/connectors/cloudflare-radar.md (generated)"],
        tools=[
            ("(wrapped tools)", "Tools come from the unified server and match `*_radar_*` (about 275 endpoint tools per the Hermes manifest comment). Pin the expected list in `mcp/cloudflare-radar/expected_tools.txt` at build time, and let `connector-health.yml` open a drift issue when it changes. The `radar-au` skill maps questions to them: AU layer 7 attack summary and top attack types, top source locations for attacks on AU, AU outages and traffic anomalies, BGP hijacks and leaks for an Australian ASN, domain rank for lookalike triage, and AU email authentication trends.", None),
        ],
        fixtures=["tools_list_radar.json (recorded tools/list, Radar subset)", "outages_AU.json", "l7_summary_AU.json", "bgp_hijacks.json", "radar_429_with_retry_after.json", "unauthorised_401.json"],
        wrap=True,
        extra_tests=["Render test: with no token, the entry uses `auth: oauth`; with `CLOUDFLARE_RADAR_API_TOKEN` set, it uses the bearer header and no `auth` key; `tools.include` is exactly `[\"*_radar_*\"]` in both.", "Filter test against the recorded `tools/list`: no tool outside `*_radar_*` registers, and every registered tool maps to a GET Radar endpoint."],
        extra_criteria=["No Cloudflare tool that can change an account is registered.", "Nothing depends on the deprecated dedicated Radar MCP server."],
    ),
    dict(
        key="auscert", server="auscert", name="AusCERT public security bulletins",
        group="Australian community", milestone=M_V01, priority="p1",
        docs="https://www.auscert.org.au/",
        endpoints=[("GET", "https://portal.auscert.org.au/rss/bulletins/", "Public RSS of AusCERT security bulletins (ESB and ASB)")],
        auth="None for the public RSS. Member-only portal content is out of scope.", env=[],
        rate="One request per 30 minutes.",
        cache="30 minutes, ETag aware.",
        terms="Return title, link, date and the feed summary only. Do not mirror full bulletins. Check AusCERT's terms before snapshotting.",
        hosts=["portal.auscert.org.au"],
        notes="The old `https://www.auscert.org.au/rss/bulletins/` path now returns a 404 page; the portal path works. Bulletins overlap vendor advisories, so dedupe by CVE in the intel store.",
        verified="`portal.auscert.org.au/rss/bulletins/` returned `application/rss+xml` on 16 October 2026.",
        tools=[("auscert_bulletins", "Recent AusCERT bulletins, optionally filtered by keyword or CVE.", obj({"since": DATE, "query": {"type": S}, "limit": LIMIT(20, 100)}))],
        fixtures=["bulletins.xml", "bulletins_empty.xml"],
    ),
    dict(
        key="abusech", server="abusech", name="abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker)",
        group="Global threat intelligence", milestone=M_V01, priority="p1",
        docs="https://abuse.ch/",
        endpoints=[
            ("POST", "https://urlhaus-api.abuse.ch/v1/url/ , /host/ , /payload/ ; GET /v1/urls/recent/", "URLhaus lookups"),
            ("POST", "https://threatfox-api.abuse.ch/api/v1/", "ThreatFox JSON queries: `search_ioc`, `get_iocs` (days 1 to 7), `search_hash`, `malwareinfo`"),
            ("POST", "https://mb-api.abuse.ch/api/v1/", "MalwareBazaar: `get_info` by hash, `get_recent`, `get_taginfo`"),
            ("GET", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", "Feodo Tracker botnet C2 blocklist"),
        ],
        auth="`Auth-Key` HTTP header. Free key from https://auth.abuse.ch/. Mandatory since 30 June 2025.",
        env=[("ABUSECH_AUTH_KEY", True, "abuse.ch Auth-Key, shared by URLhaus, ThreatFox and MalwareBazaar.")],
        rate="Fair use, no published number. Self-imposed 1 request a second per platform. Unauthenticated calls return 401.",
        cache="Lookups 1 hour. Recent lists 15 minutes. Feodo blocklist 1 hour.",
        terms="abuse.ch terms (effective 4 November 2025): free for not-for-profit use within query volume limits; commercial users may need a paid subscription through Spamhaus; no high-volume automated harvesting. Feodo Tracker separately states its datasets are CC0. The skill shows both statements and leaves the call to the operator.",
        default_off="abuse.ch free access is for not-for-profit use (see Terms). It ships off by default and users bring their own `ABUSECH_AUTH_KEY`.",
        hosts=["urlhaus-api.abuse.ch", "threatfox-api.abuse.ch", "mb-api.abuse.ch", "feodotracker.abuse.ch"],
        notes="No sample download tool. MalwareBazaar returns metadata only. Never write a sample to disk.",
        verified="URLhaus and ThreatFox returned 401 without a key; Feodo JSON returned 200 on 16 October 2026. Auth rules from the abuse.ch 'Community First' notice and API pages.",
        tools=[
            ("abusech_lookup", "Look up an indicator across URLhaus, ThreatFox and MalwareBazaar.", obj({"indicator": {"type": S, "minLength": 3}, "type": {"enum": ["url", "domain", "ip", "md5", "sha1", "sha256"]}}, ["indicator"])),
            ("threatfox_recent", "ThreatFox IOCs from the last N days.", obj({"days": {"type": "integer", "minimum": 1, "maximum": 7, "default": 1}, "malware": {"type": S}, "limit": LIMIT(100, 1000)})),
            ("feodo_blocklist", "Current Feodo Tracker C2 IPs, optionally filtered by country.", obj({"country": {"type": S, "pattern": "^[A-Z]{2}$"}})),
        ],
        fixtures=["urlhaus_url_hit.json", "urlhaus_no_results.json", "threatfox_get_iocs.json", "bazaar_get_info.json", "feodo_ipblocklist.json", "abusech_401.json"],
    ),
    dict(
        key="otx", server="otx", name="AlienVault OTX",
        group="Global threat intelligence", milestone=M_V02, priority="p2",
        docs="https://otx.alienvault.com/api",
        endpoints=[
            ("GET", "https://otx.alienvault.com/api/v1/indicators/<type>/<value>/<section>", "Indicator details. Types: IPv4, IPv6, domain, hostname, url, file. Sections include general, reputation, geo, malware, url_list, passive_dns"),
            ("GET", "https://otx.alienvault.com/api/v1/pulses/subscribed", "Pulses you subscribe to, `modified_since`, paged"),
            ("GET", "https://otx.alienvault.com/api/v1/search/pulses?q=", "Pulse search"),
        ],
        auth="`X-OTX-API-KEY` header.",
        env=[("OTX_API_KEY", True, "OTX API key from your OTX account settings.")],
        rate="Limits are not clearly published. Self-imposed 1 request a second, back off on 429.",
        cache="Indicators 6 hours. Subscribed pulses 1 hour.",
        terms="OTX terms of service. Pulses are community content and must be treated as untrusted text.",
        hosts=["otx.alienvault.com"],
        notes="Pulse descriptions are free text written by strangers. Wrap them as untrusted and never follow instructions inside them.",
        verified="`/api/v1/user/me` returned 'Authentication required' without a key on 16 October 2026.",
        tools=[
            ("otx_indicator", "Indicator details from one OTX section.", obj({"type": {"enum": ["IPv4", "IPv6", "domain", "hostname", "url", "file"]}, "value": {"type": S}, "section": {"type": S, "default": "general"}}, ["type", "value"])),
            ("otx_pulses", "Subscribed pulses modified since a date.", obj({"modified_since": DATE, "limit": LIMIT(20, 100)})),
        ],
        fixtures=["indicator_ipv4_general.json", "pulses_subscribed_page1.json", "otx_403.json"],
    ),
    dict(
        key="greynoise", server="greynoise", name="GreyNoise Community",
        group="Global threat intelligence", milestone=M_V02, priority="p2",
        docs="https://docs.greynoise.io/",
        endpoints=[("GET", "https://api.greynoise.io/v3/community/<ip>", "Noise and RIOT classification for one IP")],
        auth="Optional `key` header with a community key.",
        env=[("GREYNOISE_API_KEY", False, "Optional community API key.")],
        rate="Community API has a daily quota (check current figure in GreyNoise docs). Self-imposed 1 request a second.",
        cache="24 hours per IP.",
        terms="GreyNoise community terms.",
        hosts=["api.greynoise.io"],
        notes="Answers 'is this IP just internet background noise or a known benign service', which cuts triage time on scanner alerts.",
        verified="`/v3/community/1.1.1.1` returned a valid JSON body without a key on 16 October 2026.",
        tools=[("greynoise_ip", "GreyNoise community classification for an IP.", obj({"ip": IP}, ["ip"]))],
        fixtures=["community_noise.json", "community_riot.json", "community_404_unknown.json", "community_429.json"],
    ),
    dict(
        key="shodan-internetdb", server="internetdb", name="Shodan InternetDB",
        group="Global threat intelligence", milestone=M_V02, priority="p2",
        docs="https://internetdb.shodan.io/",
        endpoints=[("GET", "https://internetdb.shodan.io/<ip>", "Open ports, hostnames, CPEs, tags and vulns for one IP")],
        auth="None.", env=[],
        rate="Free, no key. Self-imposed 1 request a second.",
        cache="24 hours per IP.",
        terms="InternetDB is for non-commercial use per its page (verify wording before release).",
        hosts=["internetdb.shodan.io"],
        notes="Use for passive exposure checks only.",
        verified="`/1.1.1.1` returned JSON on 16 October 2026.",
        tools=[("internetdb_ip", "Passive exposure summary for an IP.", obj({"ip": IP}, ["ip"]))],
        fixtures=["ip_hit.json", "ip_404.json"],
    ),
    dict(
        key="mitre-attack", server="attack", name="MITRE ATT&CK (STIX 2.1)",
        group="Frameworks", milestone=M_V01, priority="p1",
        docs="https://github.com/mitre-attack/attack-stix-data",
        endpoints=[
            ("GET", "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json", "Collection index with versions"),
            ("GET", "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json", "Enterprise STIX 2.1 bundle (also mobile and ics)"),
        ],
        auth="None.", env=[],
        rate="Downloaded only when `index.json` reports a new version.",
        cache="Snapshot per ATT&CK version under `mcp/attack/data/<version>/` (indexed into SQLite at bootstrap).",
        terms="ATT&CK terms of use require attribution to MITRE.",
        hosts=["raw.githubusercontent.com"],
        notes="Store technique id, name, tactic, platforms, data sources, detections and mitigations. Skip revoked and deprecated objects by default.",
        verified="`index.json` returned HTTP 200 on 16 October 2026.",
        tools=[
            ("attack_technique", "One technique or sub-technique by id, with tactics, mitigations and detection notes.", obj({"technique_id": {"type": S, "pattern": "^T\\d{4}(\\.\\d{3})?$"}}, ["technique_id"])),
            ("attack_search", "Search techniques, groups and software by keyword.", obj({"query": {"type": S}, "domain": {"enum": ["enterprise", "mobile", "ics"], "default": "enterprise"}, "limit": LIMIT(10, 50)}, ["query"])),
            ("attack_group", "One threat group with aliases and associated techniques.", obj({"name_or_id": {"type": S}}, ["name_or_id"])),
        ],
        fixtures=["index.json", "enterprise-attack.min.json (trimmed bundle)"],
    ),
    dict(
        key="sigma", server="sigma", name="SigmaHQ detection rules",
        group="Frameworks", milestone=M_V02, priority="p1",
        docs="https://github.com/SigmaHQ/sigma",
        endpoints=[("GET", "https://api.github.com/repos/SigmaHQ/sigma/releases/latest", "Release with rule packages (core, core+, emerging threats)")],
        auth="None. Optional `GITHUB_TOKEN`.",
        env=[("GITHUB_TOKEN", False, "Optional, raises GitHub API limits.")],
        rate="GitHub API limits. One download per release.",
        cache="Snapshot per release under `mcp/sigma/data/<tag>/`.",
        terms="Sigma rules are under the Detection Rule License (DRL) 1.1, which requires attribution. Keep `author` and `id` on every rule shown.",
        hosts=["api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"],
        notes="Conversion uses pySigma with the Kusto backend for Microsoft Sentinel and Defender KQL. Check the current pySigma backend package names on PyPI before pinning.",
        verified="SigmaHQ/sigma is public.",
        tools=[
            ("sigma_search", "Search rules by keyword, ATT&CK technique, log source or level.", obj({"query": {"type": S}, "technique_id": {"type": S}, "product": {"type": S}, "service": {"type": S}, "level": {"enum": ["informational", "low", "medium", "high", "critical"]}, "limit": LIMIT(10, 50)})),
            ("sigma_get", "One rule by id, as YAML.", obj({"rule_id": {"type": S, "format": "uuid"}}, ["rule_id"])),
            ("sigma_convert", "Convert a stored rule or supplied YAML to a query language.", obj({"rule_id": {"type": S}, "rule_yaml": {"type": S, "maxLength": 20000}, "target": {"enum": ["kusto", "splunk", "elasticsearch"]}}, ["target"])),
        ],
        fixtures=["release_latest.json", "rules_subset.zip (10 rules)", "rule_with_unsupported_modifier.yml"],
    ),
    dict(
        key="crtsh", server="crtsh", name="crt.sh certificate transparency",
        group="Global threat intelligence", milestone=M_V02, priority="p2",
        docs="https://crt.sh/",
        endpoints=[("GET", "https://crt.sh/?q=<domain>&output=json", "Certificates logged for a domain (use `%.` prefix for subdomains)")],
        auth="None.", env=[],
        rate="Shared public service that is often slow. One request every 5 seconds, 90 second timeout.",
        cache="24 hours per query.",
        terms="Public CT data.",
        hosts=["crt.sh"],
        notes="Useful for lookalike domain and phishing infrastructure checks. Dedupe by serial number.",
        verified="JSON query returned HTTP 200 on 16 October 2026.",
        tools=[("crtsh_certs", "Certificates for a domain, deduplicated.", obj({"domain": {"type": S, "format": "hostname"}, "include_subdomains": {"type": "boolean", "default": True}, "include_expired": {"type": "boolean", "default": False}}, ["domain"]))],
        fixtures=["crtsh_example.json", "crtsh_timeout (simulated)", "crtsh_502.html"],
    ),
    dict(
        key="au-regulatory", server="aureg", name="Australian reporting obligations (OAIC NDB, SOCI, ransomware payments)",
        group="Australian government", milestone=M_V02, priority="p1",
        docs="https://www.oaic.gov.au/privacy/notifiable-data-breaches",
        endpoints=[
            ("GET", "https://www.oaic.gov.au/privacy/notifiable-data-breaches/quick-reference-guide-for-responding-to-data-breaches", "OAIC quick reference"),
            ("GET", "https://www.oaic.gov.au/privacy/notifiable-data-breaches/preventing-preparing-for-and-responding-to-data-breaches/data-breach-preparation-and-response/part-4-notifiable-data-breach-ndb-scheme", "OAIC NDB scheme detail"),
            ("GET", "https://www.cyber.gov.au/report-a-cyber-security-incident", "SOCI Part 2B reporting to ASD's ACSC"),
            ("GET", "https://www.cisc.gov.au/resources-subsite/Documents/ncsi-guidance.pdf", "CISC notification guidance"),
            ("GET", "https://www.legislation.gov.au/", "Primary legislation: Privacy Act 1988 Part IIIC, SOCI Act 2018 ss 30BC and 30BD, Cyber Security Act 2024 ransomware payment reporting (confirm section numbers on the register)"),
        ],
        auth="None.", env=[],
        rate="Fetched only by the regeneration workflow, once a week, 1 request every 5 seconds.",
        cache="Shipped snapshot `mcp/aureg/data/obligations-<date>.json`, each rule carrying the quoted source sentence, URL, retrieval date and SHA-256.",
        terms="Government content. Quote short passages with attribution. This is guidance, not legal advice, and every answer says so.",
        hosts=["www.oaic.gov.au", "www.cyber.gov.au", "www.cisc.gov.au", "www.legislation.gov.au"],
        notes="Verified rules to encode: NDB requires a reasonable assessment of a suspected eligible data breach within 30 days, then notification to affected individuals and the OAIC as soon as practicable. SOCI: critical incidents with significant impact on availability within 12 hours (written record within 84 hours of an oral report), other incidents with relevant impact within 72 hours (written record within 48 hours). The ransomware payment reporting rule must be confirmed from the Cyber Security Act 2024 text before it is encoded.",
        verified="OAIC guidance pages, cyber.gov.au reporting page, CISC guidance PDF and SOCI s 30BC on AustLII reviewed via search on 16 October 2026.",
        tools=[
            ("aureg_obligation", "Return the encoded rule, deadline and quoted source text for a regime and trigger.", obj({"regime": {"enum": ["ndb", "soci", "ransomware_payment"]}, "trigger": {"type": S, "description": "For example 'critical_incident', 'other_incident', 'suspected_breach'"}}, ["regime"])),
            ("aureg_deadline", "Compute deadlines in Australia/Sydney from an awareness time.", obj({"regime": {"enum": ["ndb", "soci", "ransomware_payment"]}, "trigger": {"type": S}, "aware_at": {"type": S, "format": "date-time"}}, ["regime", "trigger", "aware_at"])),
        ],
        fixtures=["oaic_quick_ref.html", "cyber_report_page.html", "cisc_ncsi_guidance.pdf (first pages)"],
    ),
    dict(
        key="junction", server="junction", name="Junction (Microsoft Graph, Defender, Sentinel)",
        group="Author's public tools", milestone=M_V02, priority="p2",
        docs="https://github.com/jusso-dev/junction",
        endpoints=[("MCP", "Junction's own MCP server", "Microsoft Graph, Entra, Intune, Defender and Sentinel operations from Microsoft's published specs")],
        auth="Microsoft Entra sign-in handled by Junction (see its README). No Microsoft secret lives in this repo.",
        env=[("JUNCTION_BIN", False, "Path to the junction binary if it is not on PATH.")],
        rate="Microsoft Graph and ARM throttling, handled by Junction.",
        cache="None in this repo. Junction manages its own.",
        terms="Junction is MIT and not affiliated with Microsoft. Microsoft API terms apply.",
        hosts=["graph.microsoft.com", "management.azure.com", "api.loganalytics.io", "login.microsoftonline.com"],
        files=["mcp/servers.yaml (junction entry, disabled by default)", "skills/threat-hunting/references/junction.md", "tests/integration/test_junction_tools_list.py", "docs/connectors/junction.md"],
        config="""```yaml
mcp_servers:
  junction:
    command: "${JUNCTION_BIN}"      # copy the real MCP launch args from Junction's README
    args: ["mcp"]                   # placeholder: verify
    enabled: false
    trust: untrusted
    tools:
      include: ["<read-only operation tools used by skills>"]
```
Use `trust: untrusted` so any tool without `readOnlyHint: true` asks first, and fails closed in cron.""",
        notes="Integration only: ship a disabled `mcp_servers.junction` entry with `trust: untrusted` and a `tools.include` list limited to read operations used by the skills (Sentinel query, Defender incidents list, sign-in logs). Copy the exact MCP launch command from Junction's README at implementation time.",
        verified="jusso-dev/junction is public; README describes CLI, MCP and local HTTP API.",
        tools=[("(Junction tools)", "Use Junction's own tool names; filter with `tools.include`.", obj({}))],
        fixtures=["recorded MCP tools/list response from a pinned Junction release"],
    ),
    dict(
        key="brolga", server="brolga", name="Brolga threat intel context engine",
        group="Author's public tools", milestone=M_V10, priority="p3",
        docs="https://github.com/jusso-dev/Brolga",
        endpoints=[("GET", "http://127.0.0.1:8787/api/v1/health and /api/v1/stats (see Brolga docs/API.md for lookup routes)", "Read-only HTTP API served by `brolga serve`")],
        auth="Bearer token.",
        env=[("BROLGA_URL", False, "Default http://127.0.0.1:8787"), ("BROLGA_API_TOKEN", True, "Token set when starting brolga serve.")],
        rate="Local service. 20 requests a second.",
        cache="5 minutes.",
        terms="Brolga's own licence.",
        hosts=["127.0.0.1", "localhost"],
        notes="Optional bridge for teams that already run Brolga. Read the lookup routes from Brolga's docs/API.md; do not guess them.",
        verified="jusso-dev/Brolga is public; README documents `brolga serve`, health and stats routes and `BROLGA_API_TOKEN`.",
        tools=[("brolga_lookup", "Context for an indicator from a local Brolga instance.", obj({"indicator": {"type": S}}, ["indicator"]))],
        fixtures=["health.json", "stats.json", "lookup_hit.json"],
    ),
    dict(
        key="threatsieve", server="threatsieve", name="ThreatSieve",
        group="Author's public tools", milestone=M_V10, priority="p3",
        docs="https://github.com/jusso-dev/ThreatSieve",
        endpoints=[("CLI/HTTP", "`pnpm --silent cli assess <indicator> --json` or the local API on 127.0.0.1:8787", "Evidence-backed indicator assessment")],
        auth="ThreatSieve scoped API key for the HTTP API.",
        env=[("THREATSIEVE_URL", False, "Base URL of a ThreatSieve API"), ("THREATSIEVE_API_KEY", False, "Scoped API key")],
        rate="Deployment dependent. 5 requests a second default.",
        cache="15 minutes.",
        terms="ThreatSieve's own licence.",
        hosts=["127.0.0.1", "localhost"],
        notes="Optional bridge. Takes the API route list from ThreatSieve docs/api.md at implementation time.",
        verified="jusso-dev/ThreatSieve is public; README documents the CLI `assess` command and local API.",
        tools=[("threatsieve_assess", "Assessment for an indicator from a ThreatSieve instance.", obj({"indicator": {"type": S}}, ["indicator"]))],
        fixtures=["assess_domain.json", "assess_unknown.json"],
    ),
    dict(
        key="m365-secure", server="(none)", name="M365-Secure assessment reports",
        group="Author's public tools", milestone=M_V02, priority="p2",
        docs="https://github.com/jusso-dev/M365-Secure",
        endpoints=[("File", "JSON report written by `m365-assess`", "Microsoft 365 configuration findings with framework references")],
        auth="None in this repo. The user runs M365-Secure themselves.", env=[],
        rate="Not applicable.", cache="Not applicable.",
        terms="M365-Secure's own licence.", hosts=[],
        files=["plugins/cyber-au/evidence/m365_secure.py", "plugins/cyber-au/evidence/schema/m365_secure_report.schema.json", "tests/plugin/test_evidence_m365_secure.py", "docs/connectors/m365-secure.md"],
        notes="Not an MCP server. A parser in `plugins/cyber-au/evidence/m365_secure.py` reads the JSON report so the Essential Eight and Essentials skill can use it as evidence. Confirm the report schema from the tool's source.",
        verified="jusso-dev/M365-Secure is public; README documents HTML, CSV and JSON reports.",
        tools=[("evidence_import", "Import an M365-Secure JSON report as assessment evidence (plugin tool).", obj({"path": {"type": S}}, ["path"]))],
        fixtures=["m365_secure_report_sample.json (synthetic)"],
    ),
]
