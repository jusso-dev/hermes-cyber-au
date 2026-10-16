---
key: "conn-cloudflare-urlscanner"
title: "Connector: Cloudflare URL Scanner (unlisted scans, approval-gated) (`cfscan`)"
labels: ["type:feature", "area:connectors", "priority:p2"]
milestone: "v0.2"
parent: "epic-connectors"
---
## Outcome
A read-only `cfscan` connector for Cloudflare URL Scanner (unlisted scans, approval-gated) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Thin first-party facade rather than the unified server, because the unified server would expose the submit endpoint without the Unlisted guarantee. Read tools can also be reached through the unified server under `*_accounts_urlscanner_*`, which Hermes's own catalog entry excludes by default.

Docs: https://developers.cloudflare.com/radar/investigate/url-scanner/

Verified on 16 October 2026: Listed by a second inventory on 16 October 2026: docs, token permission, retention and visibility default read from Cloudflare's URL Scanner documentation.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `POST` | https://api.cloudflare.com/client/v4/accounts/{account_id}/urlscanner/v2/scan | Submit a scan. Must send `visibility: Unlisted` |
| `GET` | https://api.cloudflare.com/client/v4/accounts/{account_id}/urlscanner/v2/result/{scan_id} | Result; 404 until finished, poll every 10 to 30 seconds |

- Auth: Cloudflare API token with Account > URL Scanner > Edit.
- Rate limits: Cloudflare client API limits apply. Bulk submit up to 100 URLs; this connector submits one at a time.
- Terms and attribution: Scans default to Public on Cloudflare's side and appear in the recent scans list, so an internal URL could be published. This connector always sends Unlisted.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.cloudflare.com`

## Default state: off, bring your own key
Submitting a scan is a write to a third party. Ships with `enabled: false`, and every submit needs human approval.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.cfscan` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/cloudflare-urlscanner.md`, which quotes the terms.
- The skill text that uses it states the terms before the first call in a session.

## Files
- `mcp/cloudflare-urlscanner/src/cyberau_cloudflare_urlscanner/source.py`
- `mcp/cloudflare-urlscanner/schema/*.json`
- `mcp/cloudflare-urlscanner/tests/test_cloudflare_urlscanner.py`
- `mcp/cloudflare-urlscanner/SOURCE.md`
- `docs/connectors/cloudflare-urlscanner.md` (generated)

## Tools
### `urlscan_submit_unlisted`
Submit a URL with Unlisted visibility, after human approval.

Model-facing name: `mcp__cfscan__urlscan_submit_unlisted` (36 characters).

Input schema (`mcp/cloudflare-urlscanner/schema/urlscan_submit_unlisted.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "url": {
      "type": "string",
      "format": "uri"
    },
    "approval_token": {
      "type": "string"
    }
  },
  "required": [
    "url",
    "approval_token"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `urlscan_get_result`
Poll and return verdict, final URL, IPs and ASNs.

Model-facing name: `mcp__cfscan__urlscan_get_result` (31 characters).

Input schema (`mcp/cloudflare-urlscanner/schema/urlscan_get_result.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "scan_id": {
      "type": "string"
    }
  },
  "required": [
    "scan_id"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `CLOUDFLARE_URLSCAN_API_TOKEN` | yes | Token scoped to URL Scanner only. |
| `CLOUDFLARE_ACCOUNT_ID` | yes | Account id for the scan endpoints. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  cfscan:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "cloudflare-urlscanner"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      CLOUDFLARE_URLSCAN_API_TOKEN: "${CLOUDFLARE_URLSCAN_API_TOKEN}"
      CLOUDFLARE_ACCOUNT_ID: "${CLOUDFLARE_ACCOUNT_ID}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Results kept in the intel store; Cloudflare keeps successful scans 12 months.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/cloudflare-urlscanner/tests/fixtures/submit_response.json`
- `mcp/cloudflare-urlscanner/tests/fixtures/result_404_in_progress.json`
- `mcp/cloudflare-urlscanner/tests/fixtures/result_malicious.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- default state: a fresh install with the key present still renders `enabled: false`; an update keeps the user's `enabled: true`.
- Every submit request body in every cassette contains `"visibility": "Unlisted"` (asserted).
- Submit without a valid approval token is refused before any network call.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `cloudflare-urlscanner`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health cloudflare-urlscanner --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/cloudflare-urlscanner.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] Ships disabled (`enabled: false`) with the terms shown in docs, doctor and skill text; bootstrap and `hermes profile update` never enable it.
- [ ] No code path can submit a Public scan.

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
