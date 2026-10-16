---
key: "conn-ncsc-nz"
title: "Connector: NCSC NZ alerts (formerly CERT NZ) (`ncscnz`)"
labels: ["type:feature", "area:connectors", "priority:p2"]
milestone: "v0.2"
parent: "epic-connectors"
---
## Outcome
A read-only `ncscnz` connector for NCSC NZ alerts (formerly CERT NZ) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Neighbour-country alerts often overlap ASD alerts and sometimes arrive earlier. HTML scraping is brittle, so the schema drift check covers the list selectors. Dedupe 'UPDATED:' alerts by URL.

Docs: https://www.ncsc.govt.nz/alerts/

Verified on 16 October 2026: `/alerts/` returned 200 from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026, which found no RSS (several guessed feed paths returned 404).

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://www.ncsc.govt.nz/alerts/?start=N | HTML alert list with pagination. No RSS found; cert.govt.nz redirects here |

- Auth: None.
- Rate limits: One list page per hour, item pages at most 1 every 5 seconds.
- Terms and attribution: Licence not confirmed. Return title, date, link and extracted CVEs; quote short passages only.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `www.ncsc.govt.nz`

## Files
- `mcp/ncsc-nz/src/cyberau_ncsc_nz/source.py`
- `mcp/ncsc-nz/schema/*.json`
- `mcp/ncsc-nz/tests/test_ncsc_nz.py`
- `mcp/ncsc-nz/SOURCE.md`
- `docs/connectors/ncsc-nz.md` (generated)

## Tools
### `ncscnz_list_alerts`
Recent alerts with title, date and link.

Model-facing name: `mcp__ncscnz__ncscnz_list_alerts` (31 characters).

Input schema (`mcp/ncsc-nz/schema/ncscnz_list_alerts.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "since": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, interpreted in Australia/Sydney"
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 100,
      "default": 20
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `ncscnz_get_alert`
One alert as cleaned text with extracted CVEs.

Model-facing name: `mcp__ncscnz__ncscnz_get_alert` (29 characters).

Input schema (`mcp/ncsc-nz/schema/ncscnz_get_alert.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "url": {
      "type": "string",
      "format": "uri",
      "pattern": "^https://www\\.ncsc\\.govt\\.nz/"
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
  ncscnz:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "ncsc-nz"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: List 1 hour, items 7 days.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/ncsc-nz/tests/fixtures/alerts_page.html`
- `mcp/ncsc-nz/tests/fixtures/alert_updated_repeat.html`
- `mcp/ncsc-nz/tests/fixtures/alert_no_date.html`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `ncsc-nz`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health ncsc-nz --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/ncsc-nz.md` generated and linked from the README table.
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
