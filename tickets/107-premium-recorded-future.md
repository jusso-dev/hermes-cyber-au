---
key: "premium-recorded-future"
title: "Premium connector: Recorded Future (identity exposures and playbook alerts) (`recordedfuture`)"
labels: ["type:feature", "area:connectors", "area:premium-feeds", "priority:p3"]
milestone: "v1.0"
parent: "epic-premium"
---
## Outcome
A read-only `recordedfuture` connector for Recorded Future (identity exposures and playbook alerts) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Confirm each endpoint and method against docs.recordedfuture.com at build time; the vendor's own docs ask integrators to use them as the only source.

Docs: https://docs.recordedfuture.com/reference/get-started

Verified on 16 October 2026: Vendor docs (docs.recordedfuture.com): authentication table (`X-RFToken`, base URL) and the identity search and playbook alert reference pages. A bad token got 401 from the build box on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `POST` | https://api.recordedfuture.com/identity/credentials/search | Compromised identities for up to 100 domains; `domain_types` Email or Authorization; `limit` up to 1,000 |
| `POST` | https://api.recordedfuture.com/playbook-alert/search | Playbook alerts, filter by category such as `identity_novel_exposures` |
| `GET` | https://api.recordedfuture.com/playbook-alert/identity_novel_exposures/{id} | One identity exposure alert |

- Auth: `X-RFToken` header. Tokens are created by an Enterprise Administrator; entitlements follow the licensed modules.
- Rate limits: Not published in the overview. Back off on 429.
- Terms and attribution: Commercial licence. Default flags: metadata only, no STIX export.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.recordedfuture.com`

## Default state: off, bring your own key
Paid feed. Ships with `enabled: false`; bring your own licence.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.recordedfuture` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/recorded-future.md`, which quotes the terms.
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

Quota defaults go in `mcp/premium/vendors.yaml` from the rate limits above; the user sets `monthly_budget_units`.## Files
- `mcp/recorded-future/src/cyberau_recorded_future/source.py`
- `mcp/recorded-future/schema/*.json`
- `mcp/recorded-future/tests/test_recorded_future.py`
- `mcp/recorded-future/SOURCE.md`
- `docs/connectors/recorded-future.md` (generated)

## Tools
### `rf_identity_exposure`
Compromised identities for watchlist domains: counts by malware family and exposure type. No secrets.

Model-facing name: `mcp__recordedfuture__rf_identity_exposure` (41 characters).

Input schema (`mcp/recorded-future/schema/rf_identity_exposure.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "domains": {
      "type": "array",
      "items": {
        "type": "string",
        "format": "hostname"
      },
      "minItems": 1,
      "maxItems": 50,
      "description": "Must all be on the user's org-exposure watchlist unless `allow_external` is set by the user"
    },
    "domain_types": {
      "type": "array",
      "items": {
        "enum": [
          "Email",
          "Authorization"
        ]
      }
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 1000,
      "default": 100
    }
  },
  "required": [
    "domains"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `rf_identity_alerts`
Recent identity novel exposure playbook alerts.

Model-facing name: `mcp__recordedfuture__rf_identity_alerts` (39 characters).

Input schema (`mcp/recorded-future/schema/rf_identity_alerts.input.json`):
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
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 250,
      "default": 50
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `RECORDED_FUTURE_API_TOKEN` | yes | Recorded Future API token (paid). Bring your own licence. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  recordedfuture:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "recorded-future"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      RECORDED_FUTURE_API_TOKEN: "${RECORDED_FUTURE_API_TOKEN}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: `session` for identity data; alert metadata 1 hour.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/recorded-future/tests/fixtures/identity_search_synthetic.json` (synthetic)
- `mcp/recorded-future/tests/fixtures/playbook_alert_synthetic.json` (synthetic)
- `mcp/recorded-future/tests/fixtures/rf_401.json`

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
- [ ] Contract suite passes for `recorded-future`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health recorded-future --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/recorded-future.md` generated and linked from the README table.
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
