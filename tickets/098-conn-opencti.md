---
key: "conn-opencti"
title: "Connector: OpenCTI (your own instance) (`opencti`)"
labels: ["type:feature", "area:connectors", "priority:p3"]
milestone: "v1.0"
parent: "epic-connectors"
---
## Outcome
A read-only `opencti` connector for OpenCTI (your own instance) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Wrap the vendor server once its licence is clear; until then build the two read tools on the shared client. Brolga (v1.0) is an alternative read-only context layer over OpenCTI.

Docs: https://docs.opencti.io/

Verified on 16 October 2026: `FiligranHQ/xtm-mcp` is public. Listed by a second inventory on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GRAPHQL` | <your OpenCTI instance>/graphql | Underlying API |
| `MCP` | https://github.com/FiligranHQ/xtm-mcp | Vendor MCP server; licence to confirm |

- Auth: The instance's API token.
- Rate limits: Per instance.
- Terms and attribution: Community Edition Apache-2.0; Enterprise Edition has its own licence.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): (user supplied)

## Default state: off, bring your own key
Needs the user's own instance. Ships with `enabled: false`.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.opencti` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/opencti.md`, which quotes the terms.
- The skill text that uses it states the terms before the first call in a session.

## Files
- `mcp/opencti/src/cyberau_opencti/source.py`
- `mcp/opencti/schema/*.json`
- `mcp/opencti/tests/test_opencti.py`
- `mcp/opencti/SOURCE.md`
- `docs/connectors/opencti.md` (generated)

## Tools
### `opencti_search_entities`
Actors, malware, indicators and reports.

Model-facing name: `mcp__opencti__opencti_search_entities` (37 characters).

Input schema (`mcp/opencti/schema/opencti_search_entities.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "query": {
      "type": "string",
      "minLength": 2
    },
    "types": {
      "type": "array",
      "items": {
        "type": "string"
      }
    }
  },
  "required": [
    "query"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `opencti_get_indicator_context`
Relationships and sightings for an indicator.

Model-facing name: `mcp__opencti__opencti_get_indicator_context` (43 characters).

Input schema (`mcp/opencti/schema/opencti_get_indicator_context.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "value": {
      "type": "string"
    }
  },
  "required": [
    "value"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `OPENCTI_URL` | yes | Instance URL. |
| `OPENCTI_TOKEN` | yes | API token for a read-only user. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  opencti:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "opencti"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      OPENCTI_URL: "${OPENCTI_URL}"
      OPENCTI_TOKEN: "${OPENCTI_TOKEN}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: None beyond the intel store.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/opencti/tests/fixtures/indicator_graphql.json` (synthetic)
- `mcp/opencti/tests/fixtures/paginated.json` (synthetic)
- `mcp/opencti/tests/fixtures/expired_token.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- default state: a fresh install with the key present still renders `enabled: false`; an update keeps the user's `enabled: true`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `opencti`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health opencti --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/opencti.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] Ships disabled (`enabled: false`) with the terms shown in docs, doctor and skill text; bootstrap and `hermes profile update` never enable it.

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
