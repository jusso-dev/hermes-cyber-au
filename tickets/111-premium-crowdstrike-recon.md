---
key: "premium-crowdstrike-recon"
title: "Premium connector: CrowdStrike Falcon Adversary Intelligence Recon (dark web monitoring notifications) (`csrecon`)"
labels: ["type:feature", "area:connectors", "area:premium-feeds", "priority:p3"]
milestone: "v1.0"
parent: "epic-premium"
---
## Outcome
A read-only `csrecon` connector for CrowdStrike Falcon Adversary Intelligence Recon (dark web monitoring notifications) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Use the official FalconPy SDK (public `CrowdStrike/falconpy`) rather than hand-written calls. Creating rules is out of scope; rules are managed in Falcon.

Docs: https://developer.crowdstrike.com/api-reference/collections/recon/

Verified on 16 October 2026: Vendor developer centre Recon collection page and FalconPy `recon.py`. The token endpoint returned 401 from the build box on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `POST` | https://api.crowdstrike.com/oauth2/token | OAuth2 client credentials token (use the base URL for the customer's cloud) |
| `GET` | Recon notifications query and entities endpoints (FalconPy `query_notifications`, `get_notifications`) | Notifications raised by monitoring rules |
| `GET` | Recon rules query and entities endpoints (FalconPy `query_rules`, `get_rules`) | Monitoring rules (read only here) |

- Auth: OAuth2 client credentials from an API client created in Falcon with read scope for Recon monitoring rules only.
- Rate limits: Per Falcon API limits, returned in headers. Back off on 429.
- Terms and attribution: Commercial licence. Default flags: metadata only, no STIX export.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.crowdstrike.com`

## Default state: off, bring your own key
Paid feed. Ships with `enabled: false`; bring your own licence.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.csrecon` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/crowdstrike-recon.md`, which quotes the terms.
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
- `mcp/crowdstrike-recon/src/cyberau_crowdstrike_recon/source.py`
- `mcp/crowdstrike-recon/schema/*.json`
- `mcp/crowdstrike-recon/tests/test_crowdstrike_recon.py`
- `mcp/crowdstrike-recon/SOURCE.md`
- `docs/connectors/crowdstrike-recon.md` (generated)

## Tools
### `cs_recon_notifications`
Recon notifications since a date with rule name, topic and match summary.

Model-facing name: `mcp__csrecon__cs_recon_notifications` (36 characters).

Input schema (`mcp/crowdstrike-recon/schema/cs_recon_notifications.input.json`):
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
      "maximum": 500,
      "default": 100
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `cs_recon_rules`
Monitoring rules and their topics.

Model-facing name: `mcp__csrecon__cs_recon_rules` (28 characters).

Input schema (`mcp/crowdstrike-recon/schema/cs_recon_rules.input.json`):
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
| `FALCON_CLIENT_ID` | yes | API client id (paid licence). Bring your own. |
| `FALCON_CLIENT_SECRET` | yes | API client secret. |
| `FALCON_BASE_URL` | no | Cloud base URL if not the default. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  csrecon:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "crowdstrike-recon"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      FALCON_CLIENT_ID: "${FALCON_CLIENT_ID}"
      FALCON_CLIENT_SECRET: "${FALCON_CLIENT_SECRET}"
      FALCON_BASE_URL: "${FALCON_BASE_URL}"
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
- `mcp/crowdstrike-recon/tests/fixtures/notifications_synthetic.json` (synthetic)
- `mcp/crowdstrike-recon/tests/fixtures/rules_synthetic.json` (synthetic)
- `mcp/crowdstrike-recon/tests/fixtures/oauth_401.json`

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
- [ ] Contract suite passes for `crowdstrike-recon`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health crowdstrike-recon --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/crowdstrike-recon.md` generated and linked from the README table.
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
