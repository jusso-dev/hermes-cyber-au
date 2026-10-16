---
key: "premium-socradar"
title: "Premium connector: SOCRadar (company incidents: dark web, leaks, brand and attack surface) (`socradar`)"
labels: ["type:feature", "area:connectors", "area:premium-feeds", "priority:p3"]
milestone: "v1.0"
parent: "epic-premium"
---
## Outcome
A read-only `socradar` connector for SOCRadar (company incidents: dark web, leaks, brand and attack surface) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
One endpoint covers dark web mentions, leaked credentials, brand impersonation and attack surface alarms, so the connector maps alarm types onto the common exposure kinds.

Docs: https://socradar.io/socradar-apis/

Verified on 16 October 2026: Vendor API page (socradar.io/socradar-apis) and vendor-published integrations (Elastic, Cortex XSOAR) for the incidents v4 path and `Api-Key` header. Confirm parameters in the customer portal at build time.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://platform.socradar.com/api/company/{company_id}/incidents/v4 | Company incidents; filters `start_date`, `end_date`, `status`, `severity`, alarm types, `page`, `limit` |

- Auth: Company API key in the `Api-Key` header, plus the numeric company id.
- Rate limits: Not published publicly. Back off on 429.
- Terms and attribution: Commercial licence. Default flags: metadata only, no STIX export.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `platform.socradar.com`

## Default state: off, bring your own key
Paid feed. Ships with `enabled: false`; bring your own licence.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.socradar` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/socradar.md`, which quotes the terms.
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
- `mcp/socradar/src/cyberau_socradar/source.py`
- `mcp/socradar/schema/*.json`
- `mcp/socradar/tests/test_socradar.py`
- `mcp/socradar/SOURCE.md`
- `docs/connectors/socradar.md` (generated)

## Tools
### `socradar_incidents`
Company incidents in a date range, mapped to exposure kinds.

Model-facing name: `mcp__socradar__socradar_incidents` (33 characters).

Input schema (`mcp/socradar/schema/socradar_incidents.input.json`):
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
    "until": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, Australia/Sydney"
    },
    "severity": {
      "type": "string"
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 500,
      "default": 100
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `SOCRADAR_API_KEY` | yes | Company API key (paid). Bring your own licence. |
| `SOCRADAR_COMPANY_ID` | yes | Numeric company id. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  socradar:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "socradar"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      SOCRADAR_API_KEY: "${SOCRADAR_API_KEY}"
      SOCRADAR_COMPANY_ID: "${SOCRADAR_COMPANY_ID}"
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
- `mcp/socradar/tests/fixtures/incidents_v4_synthetic.json` (synthetic)
- `mcp/socradar/tests/fixtures/socradar_401.json`

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
- [ ] Contract suite passes for `socradar`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health socradar --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/socradar.md` generated and linked from the README table.
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
