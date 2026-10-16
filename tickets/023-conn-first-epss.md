---
key: "conn-first-epss"
title: "Connector: FIRST EPSS (`epss`)"
labels: ["type:feature", "area:connectors", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A read-only `epss` connector for FIRST EPSS that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Return `epss`, `percentile`, `date` and the model version string from the response envelope.

Docs: https://api.first.org/epss/

Verified on 16 October 2026: `/data/v1/epss?cve=CVE-2024-3400` returned HTTP 200 on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://api.first.org/data/v1/epss?cve=<comma list> | Scores and percentiles. Also `date`, `scope=time-series`, `epss-gt`, `percentile-gt`, `limit`, `offset` |
| `GET` | Daily bulk CSV linked from https://www.first.org/epss/data | Full daily file. Resolve the current URL from that page; do not hard-code a redirect target |

- Auth: None.
- Rate limits: 1,000 requests a minute for the public API (HTTP 429 above that). Batch up to 100 CVEs per call. Use the bulk CSV for anything over 1,000 CVEs.
- Terms and attribution: FIRST EPSS terms of use. Cite model version and score date from the response.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.first.org`, `www.first.org`, `epss.empiricalsecurity.com`

## Files
- `mcp/first-epss/src/cyberau_first_epss/source.py`
- `mcp/first-epss/schema/*.json`
- `mcp/first-epss/tests/test_first_epss.py`
- `mcp/first-epss/SOURCE.md`
- `docs/connectors/first-epss.md` (generated)

## Tools
### `epss_scores`
EPSS score and percentile for up to 100 CVEs.

Model-facing name: `mcp__epss__epss_scores` (22 characters).

Input schema (`mcp/first-epss/schema/epss_scores.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "cve_ids": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^CVE-\\d{4}-\\d{4,}$"
      },
      "minItems": 1,
      "maxItems": 100
    },
    "date": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, interpreted in Australia/Sydney"
    }
  },
  "required": [
    "cve_ids"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `epss_history`
Score history for one CVE over the last 30 days.

Model-facing name: `mcp__epss__epss_history` (23 characters).

Input schema (`mcp/first-epss/schema/epss_history.input.json`):
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

### `epss_top`
Highest scoring CVEs today above a threshold.

Model-facing name: `mcp__epss__epss_top` (19 characters).

Input schema (`mcp/first-epss/schema/epss_top.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "min_epss": {
      "type": "number",
      "minimum": 0,
      "maximum": 1,
      "default": 0.5
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 500,
      "default": 50
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
  epss:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "first-epss"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Scores change daily: cache 12 hours, keyed by CVE set and date. Store daily score history in the intel store.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/first-epss/tests/fixtures/epss_batch.json`
- `mcp/first-epss/tests/fixtures/epss_timeseries.json`
- `mcp/first-epss/tests/fixtures/epss_429.json`
- `mcp/first-epss/tests/fixtures/epss_unknown_cve.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `first-epss`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health first-epss --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/first-epss.md` generated and linked from the README table.
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
