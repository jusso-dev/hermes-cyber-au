---
key: "conn-scamwatch"
title: "Connector: Scamwatch alerts (`scamwatch`)"
labels: ["type:feature", "area:connectors", "priority:p3"]
milestone: "v1.0"
parent: "epic-connectors"
---
## Outcome
A read-only `scamwatch` connector for Scamwatch alerts that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Useful for phishing triage and awareness (for example ATO and myGov impersonation). The site returns 403 to plain clients, so a 403 must be reported as 'blocked', never as 'no alerts'.

Docs: https://www.scamwatch.gov.au/

Verified on 16 October 2026: Listed by a second inventory on 16 October 2026: a fetch service returned the page, curl got 403.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://www.scamwatch.gov.au/ | Homepage alerts (HTML). Statistics are an embedded Power BI report, out of scope |

- Auth: None.
- Rate limits: One request per 6 hours.
- Terms and attribution: Licence not confirmed.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `www.scamwatch.gov.au`

## Files
- `mcp/scamwatch/src/cyberau_scamwatch/source.py`
- `mcp/scamwatch/schema/*.json`
- `mcp/scamwatch/tests/test_scamwatch.py`
- `mcp/scamwatch/SOURCE.md`
- `docs/connectors/scamwatch.md` (generated)

## Tools
### `scamwatch_list_alerts`
Current scam alerts with title, date and link.

Model-facing name: `mcp__scamwatch__scamwatch_list_alerts` (37 characters).

Input schema (`mcp/scamwatch/schema/scamwatch_list_alerts.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 50,
      "default": 10
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `scamwatch_get_alert`
One alert as cleaned text.

Model-facing name: `mcp__scamwatch__scamwatch_get_alert` (35 characters).

Input schema (`mcp/scamwatch/schema/scamwatch_get_alert.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "url": {
      "type": "string",
      "format": "uri",
      "pattern": "^https://www\\.scamwatch\\.gov\\.au/"
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
  scamwatch:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "scamwatch"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: 6 hours.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/scamwatch/tests/fixtures/homepage_three_alerts.html`
- `mcp/scamwatch/tests/fixtures/scamwatch_403.html`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `scamwatch`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health scamwatch --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/scamwatch.md` generated and linked from the README table.
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
