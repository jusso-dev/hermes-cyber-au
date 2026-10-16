---
key: "premium-darkowl"
title: "Premium connector: DarkOwl Vision (dark web search) (`darkowl`)"
labels: ["type:feature", "area:connectors", "area:premium-feeds", "priority:p3"]
milestone: "v1.0"
parent: "epic-premium"
---
## Outcome
A read-only `darkowl` connector for DarkOwl Vision (dark web search) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Search returns dark web text, which is hostile content by definition: wrap every snippet with `untrusted_text`, cap length, never follow links.

Docs: https://support.darkowl.com/knowledge-base/search-api-documentation

Verified on 16 October 2026: Vendor support knowledge base: search API documentation and the authorisation header calculation page. `api.darkowl.com` answered 403 to an unsigned request from the build box on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://api.darkowl.com/api/v1/search?q=... | Search the dark web index; `sort`, `offset`, `highlight` and filters |

- Auth: HMAC-SHA1 request signing: sign method, path and a UTC `Date` header with the private key and send `Authorization: OWL <public key>:<base64 signature>`.
- Rate limits: Per licence. Back off on 429.
- Terms and attribution: Commercial licence. Default flags: no snippets stored, counts and links only, no STIX export.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.darkowl.com`

## Default state: off, bring your own key
Paid feed. Ships with `enabled: false`; bring your own licence.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.darkowl` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/darkowl.md`, which quotes the terms.
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
- `mcp/darkowl/src/cyberau_darkowl/source.py`
- `mcp/darkowl/schema/*.json`
- `mcp/darkowl/tests/test_darkowl.py`
- `mcp/darkowl/SOURCE.md`
- `docs/connectors/darkowl.md` (generated)

## Tools
### `darkowl_search_watchlist`
Search for watchlist names, brands and domains; returns hit counts, first and last seen dates and source types.

Model-facing name: `mcp__darkowl__darkowl_search_watchlist` (38 characters).

Input schema (`mcp/darkowl/schema/darkowl_search_watchlist.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "terms": {
      "type": "array",
      "items": {
        "type": "string",
        "minLength": 3
      },
      "minItems": 1,
      "maxItems": 20
    },
    "since": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD, Australia/Sydney"
    }
  },
  "required": [
    "terms"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `DARKOWL_PUBLIC_KEY` | yes | Public key (paid). Bring your own licence. |
| `DARKOWL_PRIVATE_KEY` | yes | Private key used only to sign; never logged. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  darkowl:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "darkowl"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      DARKOWL_PUBLIC_KEY: "${DARKOWL_PUBLIC_KEY}"
      DARKOWL_PRIVATE_KEY: "${DARKOWL_PRIVATE_KEY}"
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
- `mcp/darkowl/tests/fixtures/search_synthetic.json` (synthetic)
- `mcp/darkowl/tests/fixtures/signature_vector.json` (known-answer test for the HMAC)
- `mcp/darkowl/tests/fixtures/darkowl_403.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- default state: a fresh install with the key present still renders `enabled: false`; an update keeps the user's `enabled: true`.
- Known-answer test for the signature with a published-style vector generated locally; the private key never appears in logs.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `darkowl`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health darkowl --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/darkowl.md` generated and linked from the README table.
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
