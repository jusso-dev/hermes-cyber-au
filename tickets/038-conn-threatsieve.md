---
key: "conn-threatsieve"
title: "Connector: ThreatSieve (`threatsieve`)"
labels: ["type:feature", "area:connectors", "priority:p3"]
milestone: "v1.0"
parent: "epic-connectors"
---
## Outcome
A read-only `threatsieve` connector for ThreatSieve that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Optional bridge. Takes the API route list from ThreatSieve docs/api.md at implementation time.

Docs: https://github.com/jusso-dev/ThreatSieve

Verified on 16 October 2026: jusso-dev/ThreatSieve is public; README documents the CLI `assess` command and local API.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `CLI/HTTP` | `pnpm --silent cli assess <indicator> --json` or the local API on 127.0.0.1:8787 | Evidence-backed indicator assessment |

- Auth: ThreatSieve scoped API key for the HTTP API.
- Rate limits: Deployment dependent. 5 requests a second default.
- Terms and attribution: ThreatSieve's own licence.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `127.0.0.1`, `localhost`

## Files
- `mcp/threatsieve/src/cyberau_threatsieve/source.py`
- `mcp/threatsieve/schema/*.json`
- `mcp/threatsieve/tests/test_threatsieve.py`
- `mcp/threatsieve/SOURCE.md`
- `docs/connectors/threatsieve.md` (generated)

## Tools
### `threatsieve_assess`
Assessment for an indicator from a ThreatSieve instance.

Model-facing name: `mcp__threatsieve__threatsieve_assess` (36 characters).

Input schema (`mcp/threatsieve/schema/threatsieve_assess.input.json`):
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
| `THREATSIEVE_URL` | no | Base URL of a ThreatSieve API |
| `THREATSIEVE_API_KEY` | no | Scoped API key |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  threatsieve:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "threatsieve"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      THREATSIEVE_URL: "${THREATSIEVE_URL}"
      THREATSIEVE_API_KEY: "${THREATSIEVE_API_KEY}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: 15 minutes.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/threatsieve/tests/fixtures/assess_domain.json`
- `mcp/threatsieve/tests/fixtures/assess_unknown.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `threatsieve`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health threatsieve --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/threatsieve.md` generated and linked from the README table.
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
