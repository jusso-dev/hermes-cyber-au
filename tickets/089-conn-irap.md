---
key: "conn-irap"
title: "Connector: IRAP guidance (`irap`)"
labels: ["type:feature", "area:connectors", "priority:p3"]
milestone: "v1.0"
parent: "epic-connectors"
---
## Outcome
A read-only `irap` connector for IRAP guidance that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Small snapshot-backed server built the same way as the AU obligations server (`aureg`). Inherits the cyber.gov.au fetch risk and fallback plan from the ACSC connector.

Docs: https://www.cyber.gov.au/irap

Verified on 16 October 2026: Neither inventory could fetch cyber.gov.au directly on 16 October 2026; pages were seen through a search index and an earlier snapshot.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://www.cyber.gov.au/irap | IRAP overview |
| `GET` | https://www.cyber.gov.au/business-government/protecting-devices-systems/assessment-evaluation-programs/irap/irap-consumer-guide | IRAP consumer guide |

- Auth: None.
- Rate limits: Fetched only by the regeneration workflow, weekly, 1 request every 5 seconds.
- Terms and attribution: Government content. Quote short passages with attribution.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `www.cyber.gov.au`

## Files
- `mcp/irap/src/cyberau_irap/source.py`
- `mcp/irap/schema/*.json`
- `mcp/irap/tests/test_irap.py`
- `mcp/irap/SOURCE.md`
- `docs/connectors/irap.md` (generated)

## Tools
### `irap_search_guidance`
Search the IRAP pages in the snapshot.

Model-facing name: `mcp__irap__irap_search_guidance` (31 characters).

Input schema (`mcp/irap/schema/irap_search_guidance.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "query": {
      "type": "string",
      "minLength": 2
    }
  },
  "required": [
    "query"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `irap_consumer_checklist`
The consumer guide's checks as a list, each linked to its source paragraph.

Model-facing name: `mcp__irap__irap_consumer_checklist` (34 characters).

Input schema (`mcp/irap/schema/irap_consumer_checklist.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {},
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
  irap:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "irap"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Shipped snapshot with source sentence, URL, date and SHA-256 per item.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/irap/tests/fixtures/irap_consumer_guide.html` (snapshot)
- `mcp/irap/tests/fixtures/question_not_answered` (expects an explicit 'not covered')

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `irap`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health irap --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/irap.md` generated and linked from the README table.
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
