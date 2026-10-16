---
key: "conn-pspf"
title: "Connector: Protective Security Policy Framework (PSPF) (`pspf`)"
labels: ["type:feature", "area:connectors", "priority:p3"]
milestone: "v1.0"
parent: "epic-connectors"
---
## Outcome
A read-only `pspf` connector for Protective Security Policy Framework (PSPF) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Commonwealth requirements, directions and markings. Answers must cite the requirement, never invent one. The site dropped automated clients for both inventories, so this needs the same fetch fallback ladder as ASD.

Docs: https://www.protectivesecurity.gov.au/

Verified on 16 October 2026: Could not fetch on 16 October 2026 (dropped connection, HTTP 500 to a fetch service); paths from an earlier snapshot.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://www.protectivesecurity.gov.au/publications-library/pspf-page-2026 | PSPF 2026 requirements |
| `GET` | https://www.protectivesecurity.gov.au/ | Directions and publications |

- Auth: None.
- Rate limits: Regeneration workflow only, weekly.
- Terms and attribution: Licence not confirmed. Quote short passages with attribution.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `www.protectivesecurity.gov.au`

## Files
- `mcp/pspf/src/cyberau_pspf/source.py`
- `mcp/pspf/schema/*.json`
- `mcp/pspf/tests/test_pspf.py`
- `mcp/pspf/SOURCE.md`
- `docs/connectors/pspf.md` (generated)

## Tools
### `pspf_search`
Search PSPF requirements and directions in the snapshot.

Model-facing name: `mcp__pspf__pspf_search` (22 characters).

Input schema (`mcp/pspf/schema/pspf_search.input.json`):
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

### `pspf_list_directions`
Protective security directions with dates and links.

Model-facing name: `mcp__pspf__pspf_list_directions` (31 characters).

Input schema (`mcp/pspf/schema/pspf_list_directions.input.json`):
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
  pspf:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "pspf"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Shipped snapshot.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/pspf/tests/fixtures/pspf_snapshot_two_directions.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `pspf`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health pspf --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/pspf.md` generated and linked from the README table.
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
