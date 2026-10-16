---
key: "premium-ransomware-live"
title: "Connector (free): ransomware.live victim tracker (free, filter by country AU) (`ransomlive`)"
labels: ["type:feature", "area:connectors", "area:premium-feeds", "priority:p2"]
milestone: "v0.2"
parent: "epic-premium"
---
## Outcome
A read-only `ransomlive` connector for ransomware.live victim tracker (free, filter by country AU) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Clearly free, not premium; it sits in this epic because it feeds the same AU org exposure watch. The v2 docs list `/countryvictims/<code>`, but that path returned 404 from the build box on 16 October 2026, so the PRO `/victims/?country=AU` filter is primary and v2 with a client-side filter is the fallback. RansomLook (ransomlook.io) has a similar free API without a documented country filter; not wired.

Docs: https://www.ransomware.live/apidocs

Verified on 16 October 2026: PRO API OpenAPI spec (api-pro.ransomware.live/swagger.json): `X-API-KEY`, 500,000 requests a month, `country` filter. v2 `/info` and `/recentvictims` returned 200 without a key on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://api-pro.ransomware.live/victims/?country=AU | Victims filtered by ISO country code, sector, group, year and month (at least one filter required) |
| `GET` | https://api-pro.ransomware.live/victims/recent | Recent victims |
| `GET` | https://api-pro.ransomware.live/victims/search | Search by keyword |
| `GET` | https://api-pro.ransomware.live/csirt/AU | National CERT contact for a country |
| `GET` | https://api.ransomware.live/v2/recentvictims | Unauthenticated v2 fallback; filter `country == AU` client side |

- Auth: Free. The PRO API needs a free key in the `X-API-KEY` header (from ransomware.live/my). The v2 API needs no key.
- Rate limits: PRO API: 500,000 requests a month per key, 429 beyond. v2: rate limited, no number published. Self-imposed: one poll an hour.
- Terms and attribution: Free community project. Victim entries are claims scraped from criminal leak sites, not confirmed incidents. Check the site's terms before redistributing; default flags: store metadata, no STIX export of victim names.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api-pro.ransomware.live`, `api.ransomware.live`

## Default state: off, bring your own key
Free, no licence needed. Still ships with `enabled: false` because it handles victim claims; the user turns it on.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.ransomlive` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/ransomware-live.md`, which quotes the terms.
- The skill text that uses it states the terms before the first call in a session.

## Premium interface
Paid or free: **free**. Implements {{ref:premium-interface}}; results feed {{ref:premium-org-exposure}}.

| Flag | Default |
|---|---|
| `cache` | `ttl` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

Quota defaults go in `mcp/premium/vendors.yaml` from the rate limits above; the user sets `monthly_budget_units`.

## Files
- `mcp/ransomware-live/src/cyberau_ransomware_live/source.py`
- `mcp/ransomware-live/schema/*.json`
- `mcp/ransomware-live/tests/test_ransomware_live.py`
- `mcp/ransomware-live/SOURCE.md`
- `docs/connectors/ransomware-live.md` (generated)

## Tools
### `ransom_au_victims`
Leak-site claims naming Australian organisations, newest first, each marked as an unverified claim.

Model-facing name: `mcp__ransomlive__ransom_au_victims` (34 characters).

Input schema (`mcp/ransomware-live/schema/ransom_au_victims.input.json`):
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
    "sector": {
      "type": "string"
    },
    "group": {
      "type": "string"
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 500,
      "default": 50
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `ransom_watchlist_match`
Match recent claims against the org-exposure watchlist (names, brands, domains).

Model-facing name: `mcp__ransomlive__ransom_watchlist_match` (39 characters).

Input schema (`mcp/ransomware-live/schema/ransom_watchlist_match.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "days": {
      "type": "integer",
      "minimum": 1,
      "maximum": 90,
      "default": 7
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `RANSOMWARE_LIVE_API_KEY` | no | Free key for the PRO API. Without it the connector uses the v2 API. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  ransomlive:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "ransomware-live"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      RANSOMWARE_LIVE_API_KEY: "${RANSOMWARE_LIVE_API_KEY}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: 1 hour.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/ransomware-live/tests/fixtures/victims_country_AU_synthetic.json` (synthetic: invented organisation names, example domains)
- `mcp/ransomware-live/tests/fixtures/recentvictims_v2_synthetic.json` (synthetic)
- `mcp/ransomware-live/tests/fixtures/ransomlive_429.json`

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
- [ ] Contract suite passes for `ransomware-live`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health ransomware-live --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/ransomware-live.md` generated and linked from the README table.
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
