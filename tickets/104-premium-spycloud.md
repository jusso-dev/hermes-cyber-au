---
key: "premium-spycloud"
title: "Premium connector: SpyCloud Enterprise Protection (breach and malware exposure on a watchlist) (`spycloud`)"
labels: ["type:feature", "area:connectors", "area:premium-feeds", "priority:p2"]
milestone: "v0.2"
parent: "epic-premium"
---
## Outcome
A read-only `spycloud` connector for SpyCloud Enterprise Protection (breach and malware exposure on a watchlist) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Top pick for v0.2. The watchlist lives on SpyCloud's side; `doctor` compares it with the local org-exposure watchlist and reports domains missing from either.

Docs: https://docs.spycloud.com/public-sc/docs/api-guidelines

Verified on 16 October 2026: Vendor docs (docs.spycloud.com): API guidelines name the `X-API-KEY` header; reference pages document the watchlist and breach catalogue endpoints and parameters above.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://api.spycloud.io/enterprise-v2/watchlist | Records matching the customer's watchlist; filters `since`, `until`, `type` (corporate, infected, email_domain, target_domain), `watchlist_type` (email, domain, subdomain, ip), `severity`, `source_id`, `cursor` |
| `GET` | https://api.spycloud.io/enterprise-v2/breach/catalog/{id} | Breach metadata by id |

- Auth: `X-API-KEY` header with the user's key from the SpyCloud customer portal.
- Rate limits: 429 is documented; no number published in the public docs. Read the response headers and back off.
- Terms and attribution: Commercial licence. Default flags: no on-disk cache of records, metadata only in the store, no STIX export. SpyCloud can return hashed values if hashing is enabled on the key; prefer that.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.spycloud.io`

## Default state: off, bring your own key
Paid feed. Ships with `enabled: false`; bring your own licence.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.spycloud` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/spycloud.md`, which quotes the terms.
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
- `mcp/spycloud/src/cyberau_spycloud/source.py`
- `mcp/spycloud/schema/*.json`
- `mcp/spycloud/tests/test_spycloud.py`
- `mcp/spycloud/SOURCE.md`
- `docs/connectors/spycloud.md` (generated)

## Tools
### `spycloud_watchlist_exposure`
Exposure records for watchlist domains since a date, summarised by type and severity. Credential values are redacted before return.

Model-facing name: `mcp__spycloud__spycloud_watchlist_exposure` (42 characters).

Input schema (`mcp/spycloud/schema/spycloud_watchlist_exposure.input.json`):
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
    "watchlist_type": {
      "enum": [
        "email",
        "domain",
        "subdomain",
        "ip"
      ]
    },
    "type": {
      "enum": [
        "corporate",
        "infected",
        "email_domain",
        "target_domain"
      ]
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

### `spycloud_breach_info`
Metadata for one breach source: title, publish date, record count, data classes.

Model-facing name: `mcp__spycloud__spycloud_breach_info` (35 characters).

Input schema (`mcp/spycloud/schema/spycloud_breach_info.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "breach_id": {
      "type": "string"
    }
  },
  "required": [
    "breach_id"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `SPYCLOUD_API_KEY` | yes | SpyCloud Enterprise Protection API key (paid). Bring your own licence. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  spycloud:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "spycloud"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      SPYCLOUD_API_KEY: "${SPYCLOUD_API_KEY}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: `session` for records. Breach catalogue metadata 24 hours.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/spycloud/tests/fixtures/watchlist_synthetic.json` (synthetic, fake addresses on example.com.au)
- `mcp/spycloud/tests/fixtures/breach_catalog_synthetic.json` (synthetic)
- `mcp/spycloud/tests/fixtures/spycloud_403.json`
- `mcp/spycloud/tests/fixtures/spycloud_429.json`

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
- [ ] Contract suite passes for `spycloud`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health spycloud --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/spycloud.md` generated and linked from the README table.
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
