---
key: "conn-datagov-au"
title: "Connector: data.gov.au (CKAN) (`datagov`)"
labels: ["type:feature", "area:connectors", "priority:p3"]
milestone: "v1.0"
parent: "epic-connectors"
---
## Outcome
A read-only `datagov` connector for data.gov.au (CKAN) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Low direct threat value; context and sector data. A generic CKAN client is enough.

Docs: https://data.gov.au/

Verified on 16 October 2026: `status_show` returned 200 from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://data.gov.au/data/api/3/action/package_search | CKAN search |
| `GET` | https://data.gov.au/data/api/3/action/package_show | One package |

- Auth: None.
- Rate limits: One request a second.
- Terms and attribution: Per dataset, in each record's `license_id`. Datasets with no licence are flagged.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `data.gov.au`

## Files
- `mcp/datagov-au/src/cyberau_datagov_au/source.py`
- `mcp/datagov-au/schema/*.json`
- `mcp/datagov-au/tests/test_datagov_au.py`
- `mcp/datagov-au/SOURCE.md`
- `docs/connectors/datagov-au.md` (generated)

## Tools
### `datagov_search`
Packages with title, publisher, licence and resource links.

Model-facing name: `mcp__datagov__datagov_search` (28 characters).

Input schema (`mcp/datagov-au/schema/datagov_search.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "query": {
      "type": "string",
      "minLength": 2
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

### `datagov_get_package`
One package with its resources.

Model-facing name: `mcp__datagov__datagov_get_package` (33 characters).

Input schema (`mcp/datagov-au/schema/datagov_get_package.input.json`):
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

## Env vars
| Name | Required | Purpose |
|---|---|---|
| (none) | | |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  datagov:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "datagov-au"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: 24 hours.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/datagov-au/tests/fixtures/package_search.json`
- `mcp/datagov-au/tests/fixtures/package_notspecified_licence.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `datagov-au`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health datagov-au --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/datagov-au.md` generated and linked from the README table.
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
