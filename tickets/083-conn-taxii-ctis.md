---
key: "conn-taxii-ctis"
title: "Connector: Generic TAXII 2.1 reader for ASD CTIS and other TAXII sources (`taxii`)"
labels: ["type:feature", "area:connectors", "priority:p2"]
milestone: "v0.2"
parent: "epic-connectors"
---
## Outcome
A read-only `taxii` connector for Generic TAXII 2.1 reader for ASD CTIS and other TAXII sources that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
One read-only TAXII 2.1 client serves CTIS, other TAXII feeds and optionally MITRE's ATT&CK TAXII server. Contributing back to CTIS is out of scope. Onboarding: eligibility check, Network Partner form and deed, register interest in the partner portal, technical onboarding with the CTIS service desk. Pairs with Brolga (v1.0) as a context layer.

Docs: https://www.cyber.gov.au/become-a-partner

Verified on 16 October 2026: cyber.gov.au partner pages could not be fetched by either inventory (site blocks automated clients); content seen through a search index and Microsoft's public `MSFT-AU-Security/SentinelCTIS` guide.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | <api root>/collections/ | TAXII 2.1 collections the credentials can read. ASD issues the API root, collection id and credentials during CTIS onboarding |
| `GET` | <api root>/collections/{id}/objects/?added_after=... | STIX 2.1 envelope, paged with `more` and `next` |

- Auth: HTTP Basic credentials issued to an ASD Network Partner during CTIS onboarding (membership-gated, under a confidentiality deed).
- Rate limits: Not published. Microsoft's onboarding guide for Sentinel suggests polling hourly for indicators at most a month old; use that as the ceiling.
- Terms and attribution: CTIS content is covered by the Network Partner deed. It must never appear in this public repository, fixtures, logs that are shared, or exports without a TLP check.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): (user supplied API root host, added to the allowlist by `doctor --add-host` with confirmation)

## Default state: off, bring your own key
Membership-gated. Ships with `enabled: false` and no endpoint; the user adds their own onboarding details.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.taxii` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/taxii-ctis.md`, which quotes the terms.
- The skill text that uses it states the terms before the first call in a session.

## Files
- `mcp/taxii-ctis/src/cyberau_taxii_ctis/source.py`
- `mcp/taxii-ctis/schema/*.json`
- `mcp/taxii-ctis/tests/test_taxii_ctis.py`
- `mcp/taxii-ctis/SOURCE.md`
- `docs/connectors/taxii-ctis.md` (generated)

## Tools
### `taxii_list_collections`
Collections the configured credentials can read.

Model-facing name: `mcp__taxii__taxii_list_collections` (34 characters).

Input schema (`mcp/taxii-ctis/schema/taxii_list_collections.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {},
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `taxii_get_objects`
Page through STIX objects with `added_after` and type filters.

Model-facing name: `mcp__taxii__taxii_get_objects` (29 characters).

Input schema (`mcp/taxii-ctis/schema/taxii_get_objects.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "added_after": {
      "type": "string",
      "format": "date-time"
    },
    "types": {
      "type": "array",
      "items": {
        "type": "string"
      }
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

### `taxii_lookup_indicator`
Find stored indicators matching an IP, domain, URL or hash.

Model-facing name: `mcp__taxii__taxii_lookup_indicator` (34 characters).

Input schema (`mcp/taxii-ctis/schema/taxii_lookup_indicator.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "value": {
      "type": "string",
      "minLength": 3
    }
  },
  "required": [
    "value"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `taxii_sync_status`
Last sync time, object counts and errors per collection.

Model-facing name: `mcp__taxii__taxii_sync_status` (29 characters).

Input schema (`mcp/taxii-ctis/schema/taxii_sync_status.input.json`):
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
| `TAXII_API_ROOT` | yes | API root URL issued at onboarding. |
| `TAXII_COLLECTION_ID` | yes | Collection id. |
| `TAXII_USERNAME` | yes | Username. |
| `TAXII_PASSWORD` | yes | Password. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  taxii:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "taxii-ctis"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      TAXII_API_ROOT: "${TAXII_API_ROOT}"
      TAXII_COLLECTION_ID: "${TAXII_COLLECTION_ID}"
      TAXII_USERNAME: "${TAXII_USERNAME}"
      TAXII_PASSWORD: "${TAXII_PASSWORD}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Objects go into the intel store. Collection list 24 hours.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/taxii-ctis/tests/fixtures/discovery.json` (synthetic)
- `mcp/taxii-ctis/tests/fixtures/collections.json` (synthetic)
- `mcp/taxii-ctis/tests/fixtures/envelope_page1_more.json` (synthetic)
- `mcp/taxii-ctis/tests/fixtures/bundle_indicator_malware_relationship.json` (synthetic)
- `mcp/taxii-ctis/tests/fixtures/taxii_401.json`
- `mcp/taxii-ctis/tests/fixtures/indicator_expired.json` (synthetic)

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- default state: a fresh install with the key present still renders `enabled: false`; an update keeps the user's `enabled: true`.
- TLP test: objects marked TLP:AMBER or above are excluded from STIX export and briefings sent outside the profile unless the user overrides per run.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `taxii-ctis`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health taxii-ctis --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/taxii-ctis.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] Ships disabled (`enabled: false`) with the terms shown in docs, doctor and skill text; bootstrap and `hermes profile update` never enable it.
- [ ] All fixtures are synthetic; a CI check fails on any fixture whose id matches a real CTIS collection format.
- [ ] No contribution or write call exists.

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
