---
key: "conn-osv"
title: "Connector: OSV.dev open source vulnerabilities (`osv`)"
labels: ["type:feature", "area:connectors", "priority:p2"]
milestone: "v0.2"
parent: "epic-connectors"
---
## Outcome
A read-only `osv` connector for OSV.dev open source vulnerabilities that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Useful for SBOM-driven prioritisation alongside KEV and EPSS.

Docs: https://google.github.io/osv.dev/api/

Verified on 16 October 2026: `/v1/vulns/GHSA-jfh8-c2jp-5v3q` returned the Log4j record on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `POST` | https://api.osv.dev/v1/query | Query by package and version, or commit |
| `POST` | https://api.osv.dev/v1/querybatch | Batch queries |
| `GET` | https://api.osv.dev/v1/vulns/<id> | One record (GHSA, PYSEC, GO and others) |

- Auth: None.
- Rate limits: No key. Self-imposed 10 requests a second. Use querybatch for lists.
- Terms and attribution: OSV data is aggregated from many databases; keep each record's `database_specific` source and licence fields.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.osv.dev`

## Files
- `mcp/osv/src/cyberau_osv/source.py`
- `mcp/osv/schema/*.json`
- `mcp/osv/tests/test_osv.py`
- `mcp/osv/SOURCE.md`
- `docs/connectors/osv.md` (generated)

## Tools
### `osv_query`
Vulnerabilities affecting a package version.

Model-facing name: `mcp__osv__osv_query` (19 characters).

Input schema (`mcp/osv/schema/osv_query.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "ecosystem": {
      "type": "string"
    },
    "package": {
      "type": "string"
    },
    "version": {
      "type": "string"
    }
  },
  "required": [
    "ecosystem",
    "package"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `osv_get`
One OSV record by id.

Model-facing name: `mcp__osv__osv_get` (17 characters).

Input schema (`mcp/osv/schema/osv_get.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "id": {
      "type": "string"
    }
  },
  "required": [
    "id"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `osv_batch`
Up to 100 package queries in one call.

Model-facing name: `mcp__osv__osv_batch` (19 characters).

Input schema (`mcp/osv/schema/osv_batch.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "queries": {
      "type": "array",
      "maxItems": 100,
      "items": {
        "type": "object"
      }
    }
  },
  "required": [
    "queries"
  ]
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
  osv:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "osv"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Records 24 hours. Query results 6 hours.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/osv/tests/fixtures/query_pypi_jinja2.json`
- `mcp/osv/tests/fixtures/vuln_GHSA.json`
- `mcp/osv/tests/fixtures/batch.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `osv`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health osv --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/osv.md` generated and linked from the README table.
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
