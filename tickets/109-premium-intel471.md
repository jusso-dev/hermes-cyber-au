---
key: "premium-intel471"
title: "Premium connector: Intel 471 Titan (watchers, alerts, credentials and breach alerts) (`intel471`)"
labels: ["type:feature", "area:connectors", "area:premium-feeds", "priority:p3"]
milestone: "v1.0"
parent: "epic-premium"
---
## Outcome
A read-only `intel471` connector for Intel 471 Titan (watchers, alerts, credentials and breach alerts) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Watchers are configured in Titan; this connector only reads alerts and matches them to the local watchlist. Breach alerts often name victims; handle under the privacy note.

Docs: https://github.com/intel471/titan-client-python

Verified on 16 October 2026: Vendor's public OpenAPI-generated client (intel471/titan-client-python) lists the endpoints above and Basic auth. `api.intel471.com/v1/` returned 401 from the build box on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://api.intel471.com/v1/alerts | Watcher alerts; `count`, `from`, `until`, `offset`, `watcher_group` |
| `GET` | https://api.intel471.com/v1/watcherGroups , /watcherGroups/{uid}/watchers | Watcher configuration (read only here) |
| `GET` | https://api.intel471.com/v1/credentials , /credentials/occurrences , /credentialSets | Credential intelligence |
| `GET` | https://api.intel471.com/v1/breachAlerts | Breach alerts |

- Auth: HTTP Basic: the registered Intel 471 email as the username and the API key as the password.
- Rate limits: Not published in the client README. Back off on 429.
- Terms and attribution: Commercial licence. Default flags: metadata only, no STIX export.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.intel471.com`

## Default state: off, bring your own key
Paid feed. Ships with `enabled: false`; bring your own licence.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.intel471` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/intel471.md`, which quotes the terms.
- The skill text that uses it states the terms before the first call in a session.

## Premium interface
Paid or free: **paid, bring your own licence**. Implements {{ref:premium-interface}}; results feed {{ref:premium-org-exposure}}.

| Flag | Default |
|---|---|
| `cache` | `session` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

Quota defaults go in `mcp/premium/vendors.yaml` from the rate limits above; the user sets `monthly_budget_units`.

## Files
- `mcp/intel471/src/cyberau_intel471/source.py`
- `mcp/intel471/schema/*.json`
- `mcp/intel471/tests/test_intel471.py`
- `mcp/intel471/SOURCE.md`
- `docs/connectors/intel471.md` (generated)

## Tools
### `intel471_watcher_alerts`
Recent watcher alerts with watcher name, source type and timestamp.

Model-facing name: `mcp__intel471__intel471_watcher_alerts` (38 characters).

Input schema (`mcp/intel471/schema/intel471_watcher_alerts.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "since": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, Australia/Sydney"
    },
    "watcher_group": {
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

### `intel471_breach_alerts`
Breach alerts mentioning watchlist names or domains.

Model-facing name: `mcp__intel471__intel471_breach_alerts` (37 characters).

Input schema (`mcp/intel471/schema/intel471_breach_alerts.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "query": {
      "type": "string",
      "minLength": 2
    },
    "since": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, Australia/Sydney"
    }
  },
  "required": [
    "query"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `intel471_credential_exposure`
Credential occurrences for a watchlist domain, as counts.

Model-facing name: `mcp__intel471__intel471_credential_exposure` (43 characters).

Input schema (`mcp/intel471/schema/intel471_credential_exposure.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "domain": {
      "type": "string",
      "format": "hostname"
    },
    "since": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, Australia/Sydney"
    }
  },
  "required": [
    "domain"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `INTEL471_EMAIL` | yes | Registered account email. |
| `INTEL471_API_KEY` | yes | Titan API key (paid). Bring your own licence. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  intel471:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "intel471"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      INTEL471_EMAIL: "${INTEL471_EMAIL}"
      INTEL471_API_KEY: "${INTEL471_API_KEY}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: `session`; the official client's own 10 hour cache is switched off so the terms flags decide.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/intel471/tests/fixtures/alerts_synthetic.json` (synthetic)
- `mcp/intel471/tests/fixtures/breach_alerts_synthetic.json` (synthetic)
- `mcp/intel471/tests/fixtures/credentials_occurrences_synthetic.json` (synthetic)
- `mcp/intel471/tests/fixtures/intel471_401.json`

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
- [ ] Contract suite passes for `intel471`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health intel471 --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/intel471.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] Ships disabled (`enabled: false`) with the terms shown in docs, doctor and skill text; bootstrap and `hermes profile update` never enable it.
- [ ] Implements `PremiumConnector` from {{ref:premium-interface}} and passes its contract suite.
- [ ] All fixtures are synthetic or recorded against the vendor's documented test data; none contains a real victim, credential or personal information (CI check).
- [ ] Findings normalise to `ExposureFinding` with the terms flags in the Premium interface section applied.

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
