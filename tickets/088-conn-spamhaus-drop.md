---
key: "conn-spamhaus-drop"
title: "Connector: Spamhaus DROP, DROPv6 and ASN-DROP (`drop`)"
labels: ["type:feature", "area:connectors", "priority:p2"]
milestone: "v0.2"
parent: "epic-connectors"
---
## Outcome
A read-only `drop` connector for Spamhaus DROP, DROPv6 and ASN-DROP that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Very small. Answers 'is this IP or ASN run by criminals' offline once loaded.

Docs: https://www.spamhaus.org/blocklists/do-not-route-or-peer/

Verified on 16 October 2026: `drop_v4.json` returned 200 from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://www.spamhaus.org/drop/drop_v4.json | JSON lines: CIDR, SBL id, RIR |
| `GET` | https://www.spamhaus.org/drop/drop_v6.json | IPv6 |
| `GET` | https://www.spamhaus.org/drop/asndrop.json | ASNs |

- Auth: None.
- Rate limits: Update once a day and never auto-fetch more than once an hour.
- Terms and attribution: Provided free of charge; formal licence text not confirmed. Attribute Spamhaus.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `www.spamhaus.org`

## Files
- `mcp/spamhaus-drop/src/cyberau_spamhaus_drop/source.py`
- `mcp/spamhaus-drop/schema/*.json`
- `mcp/spamhaus-drop/tests/test_spamhaus_drop.py`
- `mcp/spamhaus-drop/SOURCE.md`
- `docs/connectors/spamhaus-drop.md` (generated)

## Tools
### `drop_check_ip`
Whether an IP is inside a DROP netblock, with SBL id.

Model-facing name: `mcp__drop__drop_check_ip` (24 characters).

Input schema (`mcp/spamhaus-drop/schema/drop_check_ip.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "ip": {
      "type": "string",
      "description": "IPv4 or IPv6 address",
      "format": "ip"
    }
  },
  "required": [
    "ip"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `drop_check_asn`
Whether an ASN is on ASN-DROP.

Model-facing name: `mcp__drop__drop_check_asn` (25 characters).

Input schema (`mcp/spamhaus-drop/schema/drop_check_asn.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "asn": {
      "type": "integer",
      "minimum": 1
    }
  },
  "required": [
    "asn"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `drop_list_status`
Last fetch time and entry counts.

Model-facing name: `mcp__drop__drop_list_status` (27 characters).

Input schema (`mcp/spamhaus-drop/schema/drop_list_status.input.json`):
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
  drop:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "spamhaus-drop"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: 24 hours on disk, loaded into an in-memory prefix tree.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/spamhaus-drop/tests/fixtures/drop_v4_head.json`
- `mcp/spamhaus-drop/tests/fixtures/drop_v6_head.json`
- `mcp/spamhaus-drop/tests/fixtures/asndrop_head.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- Fetch guard: a second fetch inside an hour is refused by the limiter.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `spamhaus-drop`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health spamhaus-drop --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/spamhaus-drop.md` generated and linked from the README table.
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
