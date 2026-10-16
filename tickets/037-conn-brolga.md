---
key: "conn-brolga"
title: "Connector: Brolga threat intel context engine (`brolga`)"
labels: ["type:feature", "area:connectors", "priority:p3"]
milestone: "v1.0"
parent: "epic-connectors"
---
## Outcome
A read-only `brolga` connector for Brolga threat intel context engine that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Optional bridge for teams that already run Brolga. Read the lookup routes from Brolga's docs/API.md; do not guess them.

Docs: https://github.com/jusso-dev/Brolga

Verified on 16 October 2026: jusso-dev/Brolga is public; README documents `brolga serve`, health and stats routes and `BROLGA_API_TOKEN`.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | http://127.0.0.1:8787/api/v1/health and /api/v1/stats (see Brolga docs/API.md for lookup routes) | Read-only HTTP API served by `brolga serve` |

- Auth: Bearer token.
- Rate limits: Local service. 20 requests a second.
- Terms and attribution: Brolga's own licence.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `127.0.0.1`, `localhost`

## Files
- `mcp/brolga/src/cyberau_brolga/source.py`
- `mcp/brolga/schema/*.json`
- `mcp/brolga/tests/test_brolga.py`
- `mcp/brolga/SOURCE.md`
- `docs/connectors/brolga.md` (generated)

## Tools
### `brolga_lookup`
Context for an indicator from a local Brolga instance.

Model-facing name: `mcp__brolga__brolga_lookup` (26 characters).

Input schema (`mcp/brolga/schema/brolga_lookup.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "indicator": {
      "type": "string"
    }
  },
  "required": [
    "indicator"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `BROLGA_URL` | no | Default http://127.0.0.1:8787 |
| `BROLGA_API_TOKEN` | yes | Token set when starting brolga serve. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  brolga:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "brolga"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      BROLGA_URL: "${BROLGA_URL}"
      BROLGA_API_TOKEN: "${BROLGA_API_TOKEN}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: 5 minutes.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/brolga/tests/fixtures/health.json`
- `mcp/brolga/tests/fixtures/stats.json`
- `mcp/brolga/tests/fixtures/lookup_hit.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `brolga`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health brolga --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/brolga.md` generated and linked from the README table.
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
