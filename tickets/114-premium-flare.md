---
key: "premium-flare"
title: "Premium connector: Flare threat exposure management (leaked credentials, stealer logs, leak and ransomware sites, dark web, official MCP) (`flare`)"
labels: ["type:feature", "area:connectors", "area:premium-feeds", "priority:p1"]
milestone: "v0.2"
parent: "epic-premium"
---
## Outcome
A read-only `flare` connector for Flare threat exposure management (leaked credentials, stealer logs, leak and ransomware sites, dark web, official MCP) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Maintainer priority: sits next to Recorded Future as a v0.2 vendor at p1.

Two paths, both off by default:
1. **First-party REST tools** (primary), built on the shared client with token refresh, the Search tier limiter (1 a second), the budget guard and redaction. Tenant searches are preferred because they match the user's own identifiers and do not spend Global Search quota; global searches need approval in the guard above a per-day count the user sets.
2. **Official MCP wrap** (optional, beta). A `flare_mcp` entry at `https://api.flare.io/mcp` with `trust: untrusted` and `tools.include` limited to read tools from the vendor's list: `search_tenant`, `search_global`, `search_validate_search_query`, `events_get_event`, `events_expand_event`, `events_get_event_type`, `identifiers_list`, `identifiers_explain_event`, `identifier_groups_list`, `matching_policies_list`, `severity_rules_list`, `entities_search`, `profile_get`. Tools that create or change identifiers, groups, matching policies or severity rules stay excluded. The vendor marks the server beta; pin the tool list and let connector health open a drift issue when it changes.

AU org exposure mapping:
- Flare monitors identifiers configured in the tenant (domains, brand keywords and so on). `doctor --premium` lists them read only and compares them with the local org-exposure watchlist, reporting watchlist entries Flare is not monitoring so the user can add them in Flare. The connector never creates identifiers.
- The alert routine runs `events/tenant/_search` since the last run, filtered to types `stealer_log`, `ransomleak`, `leak`, `illicit_networks`, `listing` and the credential event types, and maps them to `ExposureFinding` kinds (`infostealer_credential`, `leak_site_claim`, `breach_credential`, `dark_web_mention`).
- `ransomleak` events naming the organisation become `leak_site_claim` findings marked `vendor_reported`, and the briefing says the claim is unconfirmed.
- Credential search is by domain only by default (`DomainQuery` on watchlist email domains). Password and email queries are not exposed as tools.

Docs: https://api.docs.flare.io/introduction/getting-started

Verified on 16 October 2026: Vendor docs (api.docs.flare.io): authentication guide (API key to 1 hour token, bearer use, restricted keys and expiry), rate limits and quotas page (4 and 1 requests a second, 429 handling, `X-Flare-Global-Searches-Remaining`), Search Credentials, Search Events, List Identifier Events and the tenant events guide (paths above), and the API MCP page (server URL, OAuth or API key, `X-Flare-Tenant-Id`, tool list). Flare's July 2026 release notes announce the MCP beta. From the build box on 16 October 2026, `https://api.flare.io/mcp` answered 401 without auth.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `POST` | https://api.flare.io/tokens/generate | Exchange the API key (raw `Authorization` header) for a 1 hour API token; optional `tenant_id` |
| `GET` | https://api.flare.io/tokens/test | Check a token |
| `POST` | https://api.flare.io/firework/v4/events/tenant/_search | Events matching the tenant's monitored identifiers; filters `severity`, `type`, `estimated_created_at`; paged with `from` and `next` |
| `POST` | https://api.flare.io/firework/v4/events/identifiers/{identifier_id}/_search | Events for one identifier; also filters `tags`, `status`, `is_ignored`, `is_remediated` |
| `POST` | https://api.flare.io/firework/v4/events/identifier_groups/{identifier_group_id}/_search | Events for an identifier group |
| `GET` | https://api.flare.io/firework/v4/identifiers/ | Monitored identifiers (read only here) |
| `POST` | https://api.flare.io/firework/v4/credentials/global/_search | Global credential search by domain, auth domain, email, password or keyword; counts against the monthly Global Search quota |
| `POST` | https://api.flare.io/firework/v4/events/global/_search | Global event search; event types include `stealer_log`, `ransomleak`, `leak`, `illicit_networks`, `listing`, `forum_content`, `chat_message`, `paste`, `source_code`, `buckets`; counts against the quota |
| `MCP` | https://api.flare.io/mcp | Official Flare API MCP server (beta). OAuth or API key in `Authorization`; tenant via `X-Flare-Tenant-Id` |

- Auth: API key (from the Flare profile page, ideally a Restricted key with Read Tenant only and an expiry date) exchanged at `/tokens/generate` for a 1 hour bearer token. The connector refreshes the token before expiry and never logs either value.
- Rate limits: Per organisation: Basic tier 4 requests a second, Search tier 1 request a second; 429 `RATELIMIT_REACHED`, wait 10 seconds before retrying. Global Search has a monthly quota; each response carries `X-Flare-Global-Searches-Remaining`, which the budget guard records.
- Terms and attribution: Commercial licence. Default flags: event metadata only in the store, no STIX export of Flare content, no sharing outside the profile.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.flare.io`

## Default state: off, bring your own key
Paid feed. Ships with `enabled: false`; bring your own licence.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.flare` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/flare.md`, which quotes the terms.
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
- `mcp/flare/src/cyberau_flare/source.py`
- `mcp/flare/schema/*.json`
- `mcp/flare/tests/test_flare.py`
- `mcp/flare/SOURCE.md`
- `docs/connectors/flare.md` (generated)

## Tools
### `flare_tenant_exposure`
Events matching the tenant's identifiers since a date, mapped to exposure kinds, with severity, type, identifier and estimated creation date. No credential values.

Model-facing name: `mcp__flare__flare_tenant_exposure` (33 characters).

Input schema (`mcp/flare/schema/flare_tenant_exposure.input.json`):
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
    "types": {
      "type": "array",
      "items": {
        "enum": [
          "stealer_log",
          "ransomleak",
          "leak",
          "illicit_networks",
          "listing",
          "forum_content",
          "chat_message",
          "paste",
          "source_code",
          "buckets",
          "infected_devices",
          "valid_credential"
        ]
      }
    },
    "min_severity": {
      "enum": [
        "info",
        "low",
        "medium",
        "high",
        "critical"
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

### `flare_identifier_events`
Events for one monitored identifier, for drill-down from a briefing item.

Model-facing name: `mcp__flare__flare_identifier_events` (35 characters).

Input schema (`mcp/flare/schema/flare_identifier_events.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "identifier_id": {
      "type": "integer"
    },
    "since": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, Australia/Sydney"
    },
    "include_remediated": {
      "type": "boolean",
      "default": false
    }
  },
  "required": [
    "identifier_id"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `flare_identifiers`
Identifiers monitored in the tenant, compared with the local watchlist (missing on either side).

Model-facing name: `mcp__flare__flare_identifiers` (29 characters).

Input schema (`mcp/flare/schema/flare_identifiers.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {},
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `flare_domain_credentials`
Counts of leaked credentials for a watchlist email domain from global credential search, by source type and imported date. Spends Global Search quota; asks first above the user's daily threshold.

Model-facing name: `mcp__flare__flare_domain_credentials` (36 characters).

Input schema (`mcp/flare/schema/flare_domain_credentials.input.json`):
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

### `flare_quota_status`
Global Search searches remaining this month, from the last response header.

Model-facing name: `mcp__flare__flare_quota_status` (30 characters).

Input schema (`mcp/flare/schema/flare_quota_status.input.json`):
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
| `FLARE_API_KEY` | yes | Restricted Flare API key with Read Tenant permission and an expiry date (paid). Bring your own licence. |
| `FLARE_TENANT_ID` | no | Tenant id when the key can reach more than one tenant. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  flare:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "flare"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      FLARE_API_KEY: "${FLARE_API_KEY}"
      FLARE_TENANT_ID: "${FLARE_TENANT_ID}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: `session` for events and credentials. Identifier list 1 hour.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/flare/tests/fixtures/tenant_events_synthetic.json` (synthetic: stealer_log, ransomleak and leak events for example.com.au)
- `mcp/flare/tests/fixtures/identifier_events_synthetic.json` (synthetic)
- `mcp/flare/tests/fixtures/identifiers_synthetic.json` (synthetic)
- `mcp/flare/tests/fixtures/credentials_global_search_synthetic.json` (synthetic, counts only)
- `mcp/flare/tests/fixtures/token_generate_synthetic.json` (synthetic token, expiry in 1 hour)
- `mcp/flare/tests/fixtures/flare_429_ratelimit.json`
- `mcp/flare/tests/fixtures/flare_401.json`
- `mcp/flare/tests/fixtures/mcp_tools_list.json` (names from the vendor's published list)

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- default state: a fresh install with the key present still renders `enabled: false`; an update keeps the user's `enabled: true`.
- Token test: the client refreshes before the 1 hour expiry and retries once on 401; neither key nor token appears in logs or cassettes.
- Limiter test: two search calls inside a second are spaced by the Search tier limiter; a 429 waits 10 seconds.
- Quota test: `X-Flare-Global-Searches-Remaining` is recorded and the guard blocks global searches below a user-set floor.
- MCP filter test: write tools (`identifiers_create`, `identifier_groups_create`, `matching_policies_create`, `severity_rules_create`) never register.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `flare`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health flare --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/flare.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] Ships disabled (`enabled: false`) with the terms shown in docs, doctor and skill text; bootstrap and `hermes profile update` never enable it.
- [ ] AU org exposure skill returns Flare stealer log, leak and ransomware leak findings for a synthetic watchlist end to end.
- [ ] `doctor --premium` lists watchlist entries Flare does not monitor, without changing anything in Flare.
- [ ] The optional MCP entry renders with `enabled: false` and only the read tools listed above.
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
