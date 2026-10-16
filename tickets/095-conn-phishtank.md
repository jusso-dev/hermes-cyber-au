---
key: "conn-phishtank"
title: "Connector: PhishTank verified phishing URLs (`phish`)"
labels: ["type:feature", "area:connectors", "priority:p3"]
milestone: "v1.0"
parent: "epic-connectors"
---
## Outcome
A read-only `phish` connector for PhishTank verified phishing URLs that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Shares the `phish` server with OpenPhish and the URLhaus cache for one combined phishing check.

Docs: https://phishtank.org/developer_info.php

Verified on 16 October 2026: Developer page returned 200 from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://data.phishtank.com/data/<app key>/online-valid.json | Hourly database download (confirm path on the developer page) |

- Auth: Free application key for automated downloads; a descriptive `User-Agent` is required.
- Rate limits: Hourly at most.
- Terms and attribution: Licence not confirmed.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `data.phishtank.com`

## Files
- `mcp/phishtank/src/cyberau_phishtank/source.py`
- `mcp/phishtank/schema/*.json`
- `mcp/phishtank/tests/test_phishtank.py`
- `mcp/phishtank/SOURCE.md`
- `docs/connectors/phishtank.md` (generated)

## Tools
### `phishtank_check_url`
Whether a URL is in the cached verified-online set.

Model-facing name: `mcp__phish__phishtank_check_url` (31 characters).

Input schema (`mcp/phishtank/schema/phishtank_check_url.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "url": {
      "type": "string",
      "format": "uri"
    }
  },
  "required": [
    "url"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `PHISHTANK_APP_KEY` | no | Application key. Without it, only a few downloads a day. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  phish:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "phishtank"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      PHISHTANK_APP_KEY: "${PHISHTANK_APP_KEY}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: 1 hour.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/phishtank/tests/fixtures/online_valid_five.json` (synthetic)
- `mcp/phishtank/tests/fixtures/trailing_slash_variant`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `phishtank`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health phishtank --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/phishtank.md` generated and linked from the README table.
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
