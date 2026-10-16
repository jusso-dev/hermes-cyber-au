---
key: "conn-abusech"
title: "Connector: abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker) (`abusech`)"
labels: ["type:feature", "area:connectors", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A read-only `abusech` connector for abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
No sample download tool. MalwareBazaar returns metadata only. Never write a sample to disk.

Docs: https://abuse.ch/

Verified on 16 October 2026: URLhaus and ThreatFox returned 401 without a key; Feodo JSON returned 200 on 16 October 2026. Auth rules from the abuse.ch 'Community First' notice and API pages.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `POST` | https://urlhaus-api.abuse.ch/v1/url/ , /host/ , /payload/ ; GET /v1/urls/recent/ | URLhaus lookups |
| `POST` | https://threatfox-api.abuse.ch/api/v1/ | ThreatFox JSON queries: `search_ioc`, `get_iocs` (days 1 to 7), `search_hash`, `malwareinfo` |
| `POST` | https://mb-api.abuse.ch/api/v1/ | MalwareBazaar: `get_info` by hash, `get_recent`, `get_taginfo` |
| `GET` | https://feodotracker.abuse.ch/downloads/ipblocklist.json | Feodo Tracker botnet C2 blocklist |

- Auth: `Auth-Key` HTTP header. Free key from https://auth.abuse.ch/. Mandatory since 30 June 2025.
- Rate limits: Fair use, no published number. Self-imposed 1 request a second per platform. Unauthenticated calls return 401.
- Terms and attribution: abuse.ch terms (effective 4 November 2025): free for not-for-profit use within query volume limits; commercial users may need a paid subscription through Spamhaus; no high-volume automated harvesting. Feodo Tracker separately states its datasets are CC0. The skill shows both statements and leaves the call to the operator.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `urlhaus-api.abuse.ch`, `threatfox-api.abuse.ch`, `mb-api.abuse.ch`, `feodotracker.abuse.ch`

## Default state: off, bring your own key
abuse.ch free access is for not-for-profit use (see Terms). It ships off by default and users bring their own `ABUSECH_AUTH_KEY`.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.abusech` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/abusech.md`, which quotes the terms.
- The skill text that uses it states the terms before the first call in a session.

## Files
- `mcp/abusech/src/cyberau_abusech/source.py`
- `mcp/abusech/schema/*.json`
- `mcp/abusech/tests/test_abusech.py`
- `mcp/abusech/SOURCE.md`
- `docs/connectors/abusech.md` (generated)

## Tools
### `abusech_lookup`
Look up an indicator across URLhaus, ThreatFox and MalwareBazaar.

Model-facing name: `mcp__abusech__abusech_lookup` (28 characters).

Input schema (`mcp/abusech/schema/abusech_lookup.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "indicator": {
      "type": "string",
      "minLength": 3
    },
    "type": {
      "enum": [
        "url",
        "domain",
        "ip",
        "md5",
        "sha1",
        "sha256"
      ]
    }
  },
  "required": [
    "indicator"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `threatfox_recent`
ThreatFox IOCs from the last N days.

Model-facing name: `mcp__abusech__threatfox_recent` (30 characters).

Input schema (`mcp/abusech/schema/threatfox_recent.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "days": {
      "type": "integer",
      "minimum": 1,
      "maximum": 7,
      "default": 1
    },
    "malware": {
      "type": "string"
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 1000,
      "default": 100
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `feodo_blocklist`
Current Feodo Tracker C2 IPs, optionally filtered by country.

Model-facing name: `mcp__abusech__feodo_blocklist` (29 characters).

Input schema (`mcp/abusech/schema/feodo_blocklist.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "country": {
      "type": "string",
      "pattern": "^[A-Z]{2}$"
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `ABUSECH_AUTH_KEY` | yes | abuse.ch Auth-Key, shared by URLhaus, ThreatFox and MalwareBazaar. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  abusech:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "abusech"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      ABUSECH_AUTH_KEY: "${ABUSECH_AUTH_KEY}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Lookups 1 hour. Recent lists 15 minutes. Feodo blocklist 1 hour.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/abusech/tests/fixtures/urlhaus_url_hit.json`
- `mcp/abusech/tests/fixtures/urlhaus_no_results.json`
- `mcp/abusech/tests/fixtures/threatfox_get_iocs.json`
- `mcp/abusech/tests/fixtures/bazaar_get_info.json`
- `mcp/abusech/tests/fixtures/feodo_ipblocklist.json`
- `mcp/abusech/tests/fixtures/abusech_401.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- default state: a fresh install with the key present still renders `enabled: false`; an update keeps the user's `enabled: true`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `abusech`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health abusech --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/abusech.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] Ships disabled (`enabled: false`) with the terms shown in docs, doctor and skill text; bootstrap and `hermes profile update` never enable it.

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
