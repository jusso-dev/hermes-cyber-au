---
key: "conn-auscert-member"
title: "Connector: AusCERT member URL feed (AusMISP goes through the MISP connector) (`auscertm`)"
labels: ["type:feature", "area:connectors", "priority:p3"]
milestone: "v1.0"
parent: "epic-connectors"
---
## Outcome
A read-only `auscertm` connector for AusCERT member URL feed (AusMISP goes through the MISP connector) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Do not build until a member confirms the feed format. AusMISP is reached through the MISP connector, not here.

Docs: https://auscert.org.au/services/threat-intelligence/

Verified on 16 October 2026: Listed by a second inventory on 16 October 2026: membership and service pages read; feed format not public.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | (member URL feed, format to confirm with a member) | Malicious URL Feed |
| `MISP` | AusMISP | Use the MISP connector |

- Auth: Paid AusCERT membership.
- Rate limits: Per member terms; default hourly.
- Terms and attribution: Member terms. Member data never enters this repository or fixtures.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): (user supplied)

## Default state: off, bring your own key
Paid membership. Ships with `enabled: false`; the user supplies their own feed details.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.auscertm` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/auscert-member.md`, which quotes the terms.
- The skill text that uses it states the terms before the first call in a session.

## Files
- `mcp/auscert-member/src/cyberau_auscert_member/source.py`
- `mcp/auscert-member/schema/*.json`
- `mcp/auscert-member/tests/test_auscert_member.py`
- `mcp/auscert-member/SOURCE.md`
- `docs/connectors/auscert-member.md` (generated)

## Tools
### `auscert_url_feed_lookup`
Check a URL or domain against the cached member URL feed.

Model-facing name: `mcp__auscertm__auscert_url_feed_lookup` (38 characters).

Input schema (`mcp/auscert-member/schema/auscert_url_feed_lookup.input.json`):
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

### `auscert_url_feed_status`
Last fetch time and entry count.

Model-facing name: `mcp__auscertm__auscert_url_feed_status` (38 characters).

Input schema (`mcp/auscert-member/schema/auscert_url_feed_status.input.json`):
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
| `AUSCERT_URL_FEED` | yes | Member feed URL, supplied by the user. |
| `AUSCERT_FEED_TOKEN` | no | Credential if the feed needs one. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  auscertm:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "auscert-member"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      AUSCERT_URL_FEED: "${AUSCERT_URL_FEED}"
      AUSCERT_FEED_TOKEN: "${AUSCERT_FEED_TOKEN}"
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
- `mcp/auscert-member/tests/fixtures/url_feed_synthetic.txt` (synthetic)

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
- [ ] Contract suite passes for `auscert-member`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health auscert-member --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/auscert-member.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] Ships disabled (`enabled: false`) with the terms shown in docs, doctor and skill text; bootstrap and `hermes profile update` never enable it.

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
