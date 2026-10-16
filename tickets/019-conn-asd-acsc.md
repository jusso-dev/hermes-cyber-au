---
key: "conn-asd-acsc"
title: "Connector: ASD's ACSC alerts, advisories and publications (`asd`)"
labels: ["type:feature", "area:connectors", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A read-only `asd` connector for ASD's ACSC alerts, advisories and publications that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
The feeds are rolling windows, so items drop out. Every poll must persist each item to the intel store (`advisories` table) or it is lost. Map each item to a stable id `asd:<feed>:<sha1(link)>`.

Docs: https://www.cyber.gov.au/

Verified on 16 October 2026: `/rss/alerts`, `/rss/advisories`, `/rss/publications`, `/rss/threats` listed by two independent feed directories. Direct fetch from the build box timed out, which matches the CDN note above.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://www.cyber.gov.au/rss/alerts | RSS 2.0, rolling window of current alerts |
| `GET` | https://www.cyber.gov.au/rss/advisories | RSS 2.0, rolling window of advisories |
| `GET` | https://www.cyber.gov.au/rss/publications | RSS 2.0 |
| `GET` | https://www.cyber.gov.au/rss/threats | RSS 2.0 |
| `GET` | https://www.cyber.gov.au/rss/news | RSS 2.0 (one directory lists news at /acsc/view-all-content/news/rss; verify which is current) |
| `GET` | https://www.cyber.gov.au/<item path> | HTML item page, fetched only for links that came from the feeds |

- Auth: None.
- Rate limits: No published limit. Self-imposed: one request per feed per 10 minutes, item pages at most 1 request every 5 seconds. The CDN is known to stall some egress paths, so use a 60 second timeout, 3 retries with backoff and fall back to the last good snapshot.
- Terms and attribution: Check the cyber.gov.au copyright page for the current licence and attribution wording before shipping snapshots. Keep the attribution string in `mcp/asd/SOURCE.md`.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `www.cyber.gov.au`

## Files
- `mcp/asd-acsc/src/cyberau_asd_acsc/source.py`
- `mcp/asd-acsc/schema/*.json`
- `mcp/asd-acsc/tests/test_asd_acsc.py`
- `mcp/asd-acsc/SOURCE.md`
- `docs/connectors/asd-acsc.md` (generated)

## Tools
### `asd_list_items`
List items from one or more ASD feeds, newest first.

Model-facing name: `mcp__asd__asd_list_items` (24 characters).

Input schema (`mcp/asd-acsc/schema/asd_list_items.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "feeds": {
      "type": "array",
      "items": {
        "enum": [
          "alerts",
          "advisories",
          "publications",
          "threats",
          "news"
        ]
      },
      "default": [
        "alerts",
        "advisories"
      ]
    },
    "since": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, interpreted in Australia/Sydney"
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 100,
      "default": 20
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `asd_get_item`
Fetch one ASD item page and return cleaned text, headings, CVE ids, ATT&CK ids and links.

Model-facing name: `mcp__asd__asd_get_item` (22 characters).

Input schema (`mcp/asd-acsc/schema/asd_get_item.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "url": {
      "type": "string",
      "format": "uri",
      "pattern": "^https://www\\.cyber\\.gov\\.au/"
    }
  },
  "required": [
    "url"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `asd_search`
Search stored ASD items (intel store full text index) by keyword, CVE or vendor.

Model-facing name: `mcp__asd__asd_search` (20 characters).

Input schema (`mcp/asd-acsc/schema/asd_search.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "query": {
      "type": "string",
      "minLength": 2
    },
    "since": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, interpreted in Australia/Sydney"
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 50,
      "default": 10
    }
  },
  "required": [
    "query"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `asd_feed_status`
Last successful fetch, fetch method used (direct, HTTP/1.1 retry, snapshot, manual import), item counts and staleness per feed.

Model-facing name: `mcp__asd__asd_feed_status` (25 characters).

Input schema (`mcp/asd-acsc/schema/asd_feed_status.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "feeds": {
      "type": "array",
      "items": {
        "enum": [
          "alerts",
          "advisories",
          "publications",
          "threats",
          "news"
        ]
      }
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| (none) | | |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  asd:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "asd-acsc"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Feeds: 15 minutes, honour ETag and Last-Modified. Item pages: 7 days keyed by URL and content hash.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/asd-acsc/tests/fixtures/rss_alerts.xml`
- `mcp/asd-acsc/tests/fixtures/rss_advisories.xml`
- `mcp/asd-acsc/tests/fixtures/rss_empty.xml`
- `mcp/asd-acsc/tests/fixtures/rss_malformed.xml`
- `mcp/asd-acsc/tests/fixtures/item_advisory.html`
- `mcp/asd-acsc/tests/fixtures/timeout` (simulated)
- `mcp/asd-acsc/tests/fixtures/http_500.txt`
- `mcp/asd-acsc/tests/fixtures/connection_reset` (simulated)

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- Runtime fetch check (manual, recorded in the PR): from a real Hermes install (the installer on Linux or macOS, and the `nousresearch/hermes-agent` Docker image), run `cyberau-mcp health asd --live --verbose` and record, per feed URL: HTTP version used, status, bytes, elapsed time and whether a `User-Agent` and `Accept` header set was needed. Two independent research passes on 16 October 2026 could not fetch cyber.gov.au from build hosts (a timeout, a dropped HTTP/2 connection and an HTTP 500 from a fetch service), so this step must run on the real runtime, not CI only.
- Fallback ladder test: with the direct fetch forced to fail, the client tries (1) HTTP/1.1 with a full, honest browser-like header set that still names the project in `User-Agent`, then (2) the last good snapshot from the intel store, and returns `cache: stale` with `data_as_of` and a warning naming the failed feed. It never returns an empty list as if there were no alerts.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `asd-acsc`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health asd-acsc --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/asd-acsc.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] The runtime fetch check above has been run from a real Hermes runtime (installer and Docker), and its results are written to `mcp/asd/SOURCE.md` with the date.
- [ ] If the direct fetch still fails from the runtime, the fallback plan is in place before v0.1 ships: HTTP/1.1 retry with full headers, then last good snapshot with a staleness flag, plus a documented manual path (the user downloads the RSS in a browser and runs `cyberau-mcp import asd <file>`). `asd_feed_status` reports which rung of the ladder served the answer.
- [ ] Items that drop out of the rolling feed between polls are still answerable from the intel store.

## Constraints
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`).

## Out of scope
Any write call to the upstream service (submissions, uploads, sample downloads).

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
