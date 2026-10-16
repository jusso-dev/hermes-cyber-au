---
key: "conn-nvd"
title: "Connector: NIST National Vulnerability Database (`nvd`)"
labels: ["type:feature", "area:connectors", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A read-only `nvd` connector for NIST National Vulnerability Database that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Expect slow responses and 503s. Time out at 60 seconds and degrade to cached data with a warning.

Docs: https://nvd.nist.gov/developers/vulnerabilities

Verified on 16 October 2026: CVE API returned HTTP 200 without a key on 16 October 2026. Limits from NVD's developer start page.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://services.nvd.nist.gov/rest/json/cves/2.0 | CVE API 2.0: `cveId`, `keywordSearch`, `cpeName`, `pubStartDate`/`pubEndDate`, `lastModStartDate`/`lastModEndDate`, `hasKev`, `cvssV3Severity`, `resultsPerPage` (max 2,000), `startIndex` |
| `GET` | https://services.nvd.nist.gov/rest/json/cvehistory/2.0 | Change history |

- Auth: Optional API key in the `apiKey` request header.
- Rate limits: 5 requests per rolling 30 seconds without a key, 50 with a key. NVD asks clients to sleep about 6 seconds between requests. The limiter must enforce the rolling window, not a fixed one.
- Terms and attribution: Show the NVD notice: "This product uses data from the NVD API but is not endorsed or certified by the NVD."
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `services.nvd.nist.gov`

## Files
- `mcp/nvd/src/cyberau_nvd/source.py`
- `mcp/nvd/schema/*.json`
- `mcp/nvd/tests/test_nvd.py`
- `mcp/nvd/SOURCE.md`
- `docs/connectors/nvd.md` (generated)

## Tools
### `nvd_get_cve`
One CVE: descriptions, CVSS v3.1 and v4.0 metrics, CWEs, references, configurations summary.

Model-facing name: `mcp__nvd__nvd_get_cve` (21 characters).

Input schema (`mcp/nvd/schema/nvd_get_cve.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "cve_id": {
      "type": "string",
      "pattern": "^CVE-\\d{4}-\\d{4,}$"
    }
  },
  "required": [
    "cve_id"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `nvd_search`
Search CVEs with NVD filters.

Model-facing name: `mcp__nvd__nvd_search` (20 characters).

Input schema (`mcp/nvd/schema/nvd_search.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "keyword": {
      "type": "string"
    },
    "cpe_name": {
      "type": "string"
    },
    "published_from": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, interpreted in Australia/Sydney"
    },
    "published_to": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, interpreted in Australia/Sydney"
    },
    "kev_only": {
      "type": "boolean",
      "default": false
    },
    "cvss_v3_severity": {
      "enum": [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
      ]
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 200,
      "default": 20
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `nvd_cve_history`
Change history for one CVE.

Model-facing name: `mcp__nvd__nvd_cve_history` (25 characters).

Input schema (`mcp/nvd/schema/nvd_cve_history.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "cve_id": {
      "type": "string",
      "pattern": "^CVE-\\d{4}-\\d{4,}$"
    }
  },
  "required": [
    "cve_id"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `NVD_API_KEY` | no | Optional. Raises the limit from 5 to 50 requests per rolling 30 seconds. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  nvd:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "nvd"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      NVD_API_KEY: "${NVD_API_KEY}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: CVE records: 24 hours. Searches: 1 hour. Persist CVSS and CWE to the intel store.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/nvd/tests/fixtures/cve_CVE-2024-3400.json`
- `mcp/nvd/tests/fixtures/search_keyword_page1.json`
- `mcp/nvd/tests/fixtures/search_keyword_page2.json`
- `mcp/nvd/tests/fixtures/nvd_403_rate_limited`
- `mcp/nvd/tests/fixtures/nvd_503`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `nvd`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health nvd --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/nvd.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).

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
