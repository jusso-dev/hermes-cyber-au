---
key: "premium-recorded-future"
title: "Premium connector: Recorded Future (identity exposure, dark web and ransomware brand alerts, domain abuse, risk lists, official MCP) (`recordedfuture`)"
labels: ["type:feature", "area:connectors", "area:premium-feeds", "priority:p1"]
milestone: "v0.2"
parent: "epic-premium"
---
## Outcome
A read-only `recordedfuture` connector for Recorded Future (identity exposure, dark web and ransomware brand alerts, domain abuse, risk lists, official MCP) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Maintainer priority: a v0.2 vendor at p1.

Two paths, both off by default:
1. **First-party REST tools** (primary). Narrow, read-only tools over Identity Intelligence, Playbook Alerts and the Connect API, built on the shared client so terms flags, redaction and the budget guard apply to every byte. This is what the AU org exposure skill and routine call.
2. **Official MCP wrap** (optional). A `recordedfuture_mcp` entry pointing at `https://mcp.recordedfuture.com/mcp` with `auth: oauth`, `trust: untrusted` and a `tools.include` list frozen at build time from the vendor's published tool list (the `whoami` tool confirms the connected organisation). Only read tools are included; any tool that updates alerts or creates takedowns stays excluded. Use it for analyst questions the narrow tools do not cover.

AU org exposure mapping:
- Watchlist domains and email domains go to `identity/credentials/search` (both `Email` and `Authorization` domain types, so customer logins on the user's own sites show up) and `identity/detections` with `novel_only: true` for the alert routine.
- Watchlist brands and subsidiaries map to the organisation's Recorded Future watch lists (configured in the portal); the connector reads `dark_web_brand` and `domain_abuse` playbook alerts and matches their entities back to watchlist entries. Ransomware extortion site mentions inside Dark Web Brand alerts become `leak_site_claim` findings marked `vendor_reported`.
- Each watchlist domain is resolved once with `company/by_domain` so briefings can show Recorded Future's company risk score next to the finding.
- `third_party_risk` alerts are read only for suppliers the user lists under `suppliers:` in the watchlist (optional), and are never alerted on as the user's own exposure.

Confirm every path, method and body field against docs.recordedfuture.com at build time; the vendor asks integrators to treat those docs as the only source.

Docs: https://docs.recordedfuture.com/reference/get-started

Verified on 16 October 2026: Vendor docs (docs.recordedfuture.com, pages updated June to September 2026): authentication table (`X-RFToken`, base URLs), Identity Intelligence search, detections and lookup OpenAPI definitions, Playbook Alerts search (body fields and categories), Dark Web Brand and Domain Abuse detail pages (ransomware site mentions named in the Dark Web Brand description), Connect API company by domain and domain risk list. Vendor support centre: MCP overview (server URL, OAuth methods, single-organisation scope) and 'API & MCP Access & Usage' (unified daily limit, one tool call equals one API call). From the build box on 16 October 2026 a bad token got 401 from the REST API, and `mcp.recordedfuture.com/mcp` answered 401 without auth.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `POST` | https://api.recordedfuture.com/identity/credentials/search | Identity Intelligence: compromised identities for up to 100 domains across breach dumps and stealer logs; `domain_types` Email and/or Authorization; `filter`; `limit` 0 to 1,000; `offset` |
| `POST` | https://api.recordedfuture.com/identity/detections | Identity Intelligence: exposure detections for the organisation, with a `novel_only` filter and malware family attribution |
| `POST` | https://api.recordedfuture.com/identity/credentials/lookup | Identity Intelligence: exposure history for given identities; accepts SHA1-hashed emails (`subjects_sha1`) for privacy-preserving lookups |
| `POST` | https://api.recordedfuture.com/playbook-alert/search | Playbook alerts; body filters `category`, `statuses`, `priority`, `entity`, `created_range`, `updated_range`, `limit`, `offset`. Categories in the docs include `identity_novel_exposures`, `domain_abuse`, `third_party_risk`, `code_repo_leakage`, `cyber_vulnerability`, `malicious_sites`, `geopolitics_facility` |
| `POST` | https://api.recordedfuture.com/playbook-alert/dark_web_brand/{id} | Dark Web Brand alert detail: the organisation's brand or assets on forums, markets, Telegram channels and ransomware extortion sites |
| `POST` | https://api.recordedfuture.com/playbook-alert/domain_abuse/{id} | Domain Abuse alert detail: typosquats and phishing domains impersonating the organisation |
| `POST` | https://api.recordedfuture.com/playbook-alert/identity_novel_exposures/{id} | Identity Novel Exposures alert detail |
| `GET` | https://api.recordedfuture.com/v2/company/by_domain/{domain} | Connect API: resolve a watchlist domain to its Company entity with risk score and evidence |
| `GET` | https://api.recordedfuture.com/v2/{ip|domain|hash|url|vulnerability}/risklist | Connect API risk lists (CSV or STIX), filtered by risk rule; matching `stat` endpoints return ETag-only change checks |
| `MCP` | https://mcp.recordedfuture.com/mcp | Official Recorded Future MCP server (generally available). OAuth 2.0 client credentials for an Integration User, or browser authorisation code for a portal user; scoped to one organisation |

- Auth: REST: `X-RFToken` header; tokens are created by an Enterprise Administrator and entitlements follow licensed modules. MCP: OAuth 2.0 (Integration User client id and secret from the Integration Center, or portal sign-in).
- Rate limits: One unified Daily API Call Limit per subscription covers REST calls and MCP tool calls (one MCP tool call counts as one API call). The guard reads the user's limit from `config.yaml` and keeps the routine share under it. Back off on 429.
- Terms and attribution: Commercial licence; MCP access needs a subscription with unlimited integrations (pilot access for others runs to 31 December 2026, per the vendor). Default flags: identity and alert metadata only in the store, no STIX export of vendor content, no sharing outside the profile. Risk lists stay inside the profile.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.recordedfuture.com`, `mcp.recordedfuture.com`

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

Quota defaults go in `mcp/premium/vendors.yaml` from the rate limits above; the user sets `monthly_budget_units`.

## Files
- `mcp/recorded-future/src/cyberau_recorded_future/source.py`
- `mcp/recorded-future/schema/*.json`
- `mcp/recorded-future/tests/test_recorded_future.py`
- `mcp/recorded-future/SOURCE.md`
- `docs/connectors/recorded-future.md` (generated)

## Tools
### `rf_identity_exposure`
Compromised identities for watchlist domains: counts by exposure type (Email, Authorization), malware family and first and last seen. Returns no passwords, cookies or full usernames.

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
      },
      "default": [
        "Email",
        "Authorization"
      ]
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

### `rf_identity_detections`
New (novel) identity detections for the organisation since a date, grouped by watchlist domain and malware family. Used by the alert routine.

Model-facing name: `mcp__recordedfuture__rf_identity_detections` (43 characters).

Input schema (`mcp/recorded-future/schema/rf_identity_detections.input.json`):
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
    "novel_only": {
      "type": "boolean",
      "default": true
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

### `rf_identity_lookup_hashed`
Exposure history for specific staff identities, sent only as SHA1 hashes of email addresses. Needs approval in the guard.

Model-facing name: `mcp__recordedfuture__rf_identity_lookup_hashed` (46 characters).

Input schema (`mcp/recorded-future/schema/rf_identity_lookup_hashed.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "emails_sha1": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-f0-9]{40}$"
      },
      "minItems": 1,
      "maxItems": 100
    }
  },
  "required": [
    "emails_sha1"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `rf_brand_alerts`
Dark Web Brand and Domain Abuse playbook alerts since a date, matched to watchlist entries, with alert id, category, priority, status and summary. Ransomware site mentions are flagged.

Model-facing name: `mcp__recordedfuture__rf_brand_alerts` (36 characters).

Input schema (`mcp/recorded-future/schema/rf_brand_alerts.input.json`):
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
    "categories": {
      "type": "array",
      "items": {
        "enum": [
          "dark_web_brand",
          "domain_abuse",
          "identity_novel_exposures",
          "code_repo_leakage",
          "third_party_risk"
        ]
      },
      "default": [
        "dark_web_brand",
        "domain_abuse"
      ]
    },
    "statuses": {
      "type": "array",
      "items": {
        "type": "string"
      }
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

### `rf_alert_detail`
Detail panels for one playbook alert, with untrusted text wrapped and screenshots not fetched.

Model-facing name: `mcp__recordedfuture__rf_alert_detail` (36 characters).

Input schema (`mcp/recorded-future/schema/rf_alert_detail.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "category": {
      "enum": [
        "dark_web_brand",
        "domain_abuse",
        "identity_novel_exposures"
      ]
    },
    "alert_id": {
      "type": "string"
    }
  },
  "required": [
    "category",
    "alert_id"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `rf_company_by_domain`
Company entity, risk score and top triggered rules for a watchlist domain.

Model-facing name: `mcp__recordedfuture__rf_company_by_domain` (41 characters).

Input schema (`mcp/recorded-future/schema/rf_company_by_domain.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "domain": {
      "type": "string",
      "format": "hostname"
    }
  },
  "required": [
    "domain"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `rf_risklist_status`
Whether a risk list changed since the last fetch (ETag via the stat endpoint), and when it was last pulled.

Model-facing name: `mcp__recordedfuture__rf_risklist_status` (39 characters).

Input schema (`mcp/recorded-future/schema/rf_risklist_status.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "entity_type": {
      "enum": [
        "ip",
        "domain",
        "hash",
        "url",
        "vulnerability"
      ]
    },
    "risk_rule": {
      "type": "string",
      "description": "Risk rule name; default list when omitted"
    }
  },
  "required": [
    "entity_type"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `RECORDED_FUTURE_API_TOKEN` | yes | REST API token (paid). Bring your own licence. |
| `RECORDED_FUTURE_ORG_ID` | no | Organisation id for identity endpoints when the token covers several (`organization_id`). |
| `RECORDED_FUTURE_MCP_CLIENT_ID` | no | Integration User client id for the official MCP server. |
| `RECORDED_FUTURE_MCP_CLIENT_SECRET` | no | Integration User client secret. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  recordedfuture:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "recorded-future"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      RECORDED_FUTURE_API_TOKEN: "${RECORDED_FUTURE_API_TOKEN}"
      RECORDED_FUTURE_ORG_ID: "${RECORDED_FUTURE_ORG_ID}"
      RECORDED_FUTURE_MCP_CLIENT_ID: "${RECORDED_FUTURE_MCP_CLIENT_ID}"
      RECORDED_FUTURE_MCP_CLIENT_SECRET: "${RECORDED_FUTURE_MCP_CLIENT_SECRET}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Identity data `session` only. Playbook alert metadata 1 hour. Risk lists: fetched only when the `stat` ETag changes, cached until the next change if the contract allows local use.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/recorded-future/tests/fixtures/identity_search_synthetic.json` (synthetic: example.com.au, fake malware family counts)
- `mcp/recorded-future/tests/fixtures/identity_detections_novel_synthetic.json` (synthetic)
- `mcp/recorded-future/tests/fixtures/playbook_search_dark_web_brand_synthetic.json` (synthetic, includes a ransomware site mention of an invented company)
- `mcp/recorded-future/tests/fixtures/domain_abuse_detail_synthetic.json` (synthetic lookalikes of example.com.au)
- `mcp/recorded-future/tests/fixtures/company_by_domain_synthetic.json` (synthetic)
- `mcp/recorded-future/tests/fixtures/domain_risklist_stat_304` (ETag unchanged)
- `mcp/recorded-future/tests/fixtures/rf_401.json`
- `mcp/recorded-future/tests/fixtures/rf_429.json`
- `mcp/recorded-future/tests/fixtures/mcp_tools_list.json` (recorded tools/list from a test organisation, names only)

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- default state: a fresh install with the key present still renders `enabled: false`; an update keeps the user's `enabled: true`.
- Hashing test: `rf_identity_lookup_hashed` refuses plain email input and sends only lower-case SHA1 hex.
- Category test: alerts outside the requested categories are dropped; `third_party_risk` alerts for suppliers never become own-organisation findings.
- Budget test: a routine run stops when its share of the Daily API Call Limit is used, and MCP tool calls count one for one.
- MCP filter test: against the recorded tools list, only included read tools register; any tool whose name implies update, create or takedown is rejected by the render step.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `recorded-future`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health recorded-future --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/recorded-future.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] Ships disabled (`enabled: false`) with the terms shown in docs, doctor and skill text; bootstrap and `hermes profile update` never enable it.
- [ ] AU org exposure skill returns Recorded Future identity, dark web brand and domain abuse findings for a synthetic watchlist end to end.
- [ ] Alert routine raises one alert per new novel detection or new playbook alert, never repeats.
- [ ] The optional MCP entry renders with `auth: oauth`, `enabled: false` and a frozen `tools.include` list, and `doctor` reports the connected organisation via `whoami`.
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
