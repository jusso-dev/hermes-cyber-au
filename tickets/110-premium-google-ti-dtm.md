---
key: "premium-google-ti-dtm"
title: "Premium connector: Google Threat Intelligence Digital Threat Monitoring (formerly Mandiant) (`gtidtm`)"
labels: ["type:feature", "area:connectors", "area:premium-feeds", "priority:p3"]
milestone: "v1.0"
parent: "epic-premium"
---
## Outcome
A read-only `gtidtm` connector for Google Threat Intelligence Digital Threat Monitoring (formerly Mandiant) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Mandiant Advantage DTM moved to `www.virustotal.com/api/v3/dtm/` under Google TI. Shares the host with the VirusTotal connector but uses a different key and server entry; never reuse a Public API key here.

Docs: https://gtidocs.virustotal.com/

Verified on 16 October 2026: Vendor docs (gtidocs.virustotal.com): DTM pagination page, the Mandiant migration guide and the DTM OpenAPI reference. `x-tool` from the vendor's public `VirusTotal/gti-dev-kit`.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://www.virustotal.com/api/v3/dtm/alerts | DTM alerts; filters include `monitor_id`, `status`, `severity`, `alert_type`, `since`, `until`, `search`, `match_value`; paged with the `Link` header |
| `GET` | https://www.virustotal.com/api/v3/dtm/monitors | Monitors (read only here) |

- Auth: `x-apikey` header with a Google Threat Intelligence key, plus an `x-tool` header naming the integration (for example `hermes-cyber-au.v0.x`).
- Rate limits: Per licence. Back off on 429.
- Terms and attribution: Commercial licence. Default flags: metadata only, no STIX export.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `www.virustotal.com`

## Default state: off, bring your own key
Paid feed. Ships with `enabled: false`; bring your own licence.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.gtidtm` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/google-ti-dtm.md`, which quotes the terms.
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
- `mcp/google-ti-dtm/src/cyberau_google_ti_dtm/source.py`
- `mcp/google-ti-dtm/schema/*.json`
- `mcp/google-ti-dtm/tests/test_google_ti_dtm.py`
- `mcp/google-ti-dtm/SOURCE.md`
- `docs/connectors/google-ti-dtm.md` (generated)

## Tools
### `gti_dtm_alerts`
DTM alerts since a date, with monitor, severity, alert type and matched value.

Model-facing name: `mcp__gtidtm__gti_dtm_alerts` (27 characters).

Input schema (`mcp/google-ti-dtm/schema/gti_dtm_alerts.input.json`):
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
    "severity": {
      "enum": [
        "low",
        "medium",
        "high"
      ]
    },
    "status": {
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

### `gti_dtm_monitors`
Configured monitors and what each watches.

Model-facing name: `mcp__gtidtm__gti_dtm_monitors` (29 characters).

Input schema (`mcp/google-ti-dtm/schema/gti_dtm_monitors.input.json`):
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
| `GTI_API_KEY` | yes | Google Threat Intelligence API key with DTM entitlement (paid). Bring your own licence. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  gtidtm:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "google-ti-dtm"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      GTI_API_KEY: "${GTI_API_KEY}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: `session`.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/google-ti-dtm/tests/fixtures/dtm_alerts_synthetic.json` (synthetic)
- `mcp/google-ti-dtm/tests/fixtures/dtm_monitors_synthetic.json` (synthetic)
- `mcp/google-ti-dtm/tests/fixtures/dtm_link_header_page2` (synthetic)
- `mcp/google-ti-dtm/tests/fixtures/gti_401.json`

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
- [ ] Contract suite passes for `google-ti-dtm`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health google-ti-dtm --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/google-ti-dtm.md` generated and linked from the README table.
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
