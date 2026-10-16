---
key: "conn-auscert"
title: "Connector: AusCERT public security bulletins (`auscert`)"
labels: ["type:feature", "area:connectors", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A read-only `auscert` connector for AusCERT public security bulletins that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
The old `https://www.auscert.org.au/rss/bulletins/` path now returns a 404 page; the portal path works. Bulletins overlap vendor advisories, so dedupe by CVE in the intel store.

Docs: https://www.auscert.org.au/

Verified on 16 October 2026: `portal.auscert.org.au/rss/bulletins/` returned `application/rss+xml` on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://portal.auscert.org.au/rss/bulletins/ | Public RSS of AusCERT security bulletins (ESB and ASB) |

- Auth: None for the public RSS. Member-only portal content is out of scope.
- Rate limits: One request per 30 minutes.
- Terms and attribution: Return title, link, date and the feed summary only. Do not mirror full bulletins. Check AusCERT's terms before snapshotting.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `portal.auscert.org.au`

## Files
- `mcp/auscert/src/cyberau_auscert/source.py`
- `mcp/auscert/schema/*.json`
- `mcp/auscert/tests/test_auscert.py`
- `mcp/auscert/SOURCE.md`
- `docs/connectors/auscert.md` (generated)

## Tools
### `auscert_bulletins`
Recent AusCERT bulletins, optionally filtered by keyword or CVE.

Model-facing name: `mcp__auscert__auscert_bulletins` (31 characters).

Input schema (`mcp/auscert/schema/auscert_bulletins.input.json`):
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
    "query": {
      "type": "string"
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

## Env vars
| Name | Required | Purpose |
|---|---|---|
| (none) | | |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  auscert:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "auscert"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: 30 minutes, ETag aware.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/auscert/tests/fixtures/bulletins.xml`
- `mcp/auscert/tests/fixtures/bulletins_empty.xml`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `auscert`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health auscert --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/auscert.md` generated and linked from the README table.
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
