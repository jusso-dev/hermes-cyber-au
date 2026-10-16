---
key: "conn-openphish"
title: "Connector: OpenPhish community feed (`phish`)"
labels: ["type:feature", "area:connectors", "priority:p3"]
milestone: "v1.0"
parent: "epic-connectors"
---
## Outcome
A read-only `phish` connector for OpenPhish community feed that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Adds `phish_check_url`, which checks OpenPhish, PhishTank and URLhaus caches together.

Docs: https://openphish.com/

Verified on 16 October 2026: `feed.txt` returned a 302 from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026, which read 200 with a short feed.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://openphish.com/feed.txt | Plain text, one URL per line (answered with a redirect from the build box; follow it within the allowlist) |

- Auth: None.
- Rate limits: Hourly at most.
- Terms and attribution: Licence not confirmed. The community feed is a small sample.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `openphish.com`

## Files
- `mcp/openphish/src/cyberau_openphish/source.py`
- `mcp/openphish/schema/*.json`
- `mcp/openphish/tests/test_openphish.py`
- `mcp/openphish/SOURCE.md`
- `docs/connectors/openphish.md` (generated)

## Tools
### `phish_check_url`
Check a URL against the OpenPhish, PhishTank and URLhaus caches together.

Model-facing name: `mcp__phish__phish_check_url` (27 characters).

Input schema (`mcp/openphish/schema/phish_check_url.input.json`):
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
| (none) | | |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  phish:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "openphish"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: 1 hour; an empty feed never wipes the cache.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/openphish/tests/fixtures/feed_three_lines.txt`
- `mcp/openphish/tests/fixtures/feed_empty.txt`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `openphish`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health openphish --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/openphish.md` generated and linked from the README table.
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
