---
key: "conn-cloudflare-radar"
title: "Connector: Cloudflare Radar via Cloudflare's unified MCP server (`cloudflare_radar`)"
labels: ["type:feature", "area:connectors", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A pinned, read-only `cloudflare_radar` entry that wraps an existing MCP server for Cloudflare Radar via Cloudflare's unified MCP server, filtered to the tools listed below, with a skill that tells the agent how to use it, recorded-fixture tests and a live health probe.

## Context
Retargeted from a first-party Radar connector to a wrap of Cloudflare's unified MCP server. Cloudflare's older dedicated Radar MCP server (`cloudflare/mcp-server-cloudflare`, `apps/radar`) is marked deprecated in its README in favour of the unified server, so nothing here builds on it. Hermes ships a catalog entry for the unified server ([`optional-mcps/cloudflare/manifest.yaml`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/optional-mcps/cloudflare/manifest.yaml)), but that entry excludes `*_radar_*` by default and exposes about 1,900 account tools, so this distribution adds its own narrow server entry instead: Radar tools only, read only. `tools.include` accepts fnmatch globs ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md)), and include wins over exclude.

Docs: https://developers.cloudflare.com/radar/

Verified on 16 October 2026: `https://mcp.cloudflare.com/mcp` answered 401 without auth on 16 October 2026 (exists). Hermes manifest read at the pinned commit. Radar REST endpoint returned the expected missing-auth error. Deprecation of the dedicated Radar server per its README, checked by a second inventory on the same date.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `MCP` | https://mcp.cloudflare.com/mcp?codemode=false | Cloudflare's unified remote MCP server (github.com/cloudflare/mcp). With `codemode=false` each API endpoint is its own tool; Radar endpoints match `*_radar_*` |
| `GET` | https://api.cloudflare.com/client/v4/radar/annotations/outages | Underlying Radar API: outages, filter `location=AU` |
| `GET` | https://api.cloudflare.com/client/v4/radar/attacks/layer7/summary | Underlying Radar API: application layer attack summaries |
| `GET` | https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events , /radar/bgp/leaks/events | Underlying Radar API: BGP events |
| `GET` | https://api.cloudflare.com/client/v4/radar/ranking/top | Underlying Radar API: domain rankings |

- Auth: OAuth 2.1 through Hermes's MCP client (scope the grant to Radar read), or a custom API token with Account > Radar > Read sent as a bearer header.
- Rate limits: Cloudflare client API: 1,200 requests per 5 minutes per token; going over blocks calls for 5 minutes. Read `retry-after`.
- Terms and attribution: Cloudflare Radar API data is CC BY-NC 4.0: non-commercial use only unless you have an agreement with Cloudflare. Attribute Cloudflare Radar in every briefing that uses it.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `mcp.cloudflare.com`

## Default state: off, bring your own key
Radar data is CC BY-NC 4.0 (see Terms). The server ships with `enabled: false` and users bring their own Cloudflare token or OAuth grant.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.cloudflare_radar` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/cloudflare-radar.md`, which quotes the terms.
- The skill text that uses it states the terms before the first call in a session.

## Files
- `mcp/servers.yaml` (entry `cloudflare_radar`, wrap, no local code)
- `skills/radar-au/SKILL.md` (AU-focused question patterns, call budget, attribution)
- `mcp/cloudflare-radar/tests/test_radar_wrap.py` (config render and tool filter tests)
- `mcp/cloudflare-radar/SOURCE.md`
- `docs/connectors/cloudflare-radar.md` (generated)

## Tools
### (wrapped tools)
Tools come from the unified server and match `*_radar_*` (about 275 endpoint tools per the Hermes manifest comment). Pin the expected list in `mcp/cloudflare-radar/expected_tools.txt` at build time, and let `connector-health.yml` open a drift issue when it changes. The `radar-au` skill maps questions to them: AU layer 7 attack summary and top attack types, top source locations for attacks on AU, AU outages and traffic anomalies, BGP hijacks and leaks for an Australian ASN, domain rank for lookalike triage, and AU email authentication trends.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `CLOUDFLARE_RADAR_API_TOKEN` | no | Optional. Custom API token with only Account > Radar > Read. Without it, Hermes uses OAuth on first connect. |

## Hermes configuration
```yaml
mcp_servers:
  cloudflare_radar:
    url: "https://mcp.cloudflare.com/mcp?codemode=false"
    # Either OAuth (default) ...
    auth: oauth
    # ... or, when CLOUDFLARE_RADAR_API_TOKEN is set, bootstrap renders this instead of `auth`:
    # headers:
    #   Authorization: "Bearer ${CLOUDFLARE_RADAR_API_TOKEN}"
    tools:
      include: ["*_radar_*"]
    enabled: false        # non-commercial data terms; the user switches it on
    lazy: true
    timeout: 120
    trust: untrusted
```
Field names from [`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md) (`url`, `headers`, `auth: oauth`, `enabled`, `tools.include`). Confirm at build time that the unified server accepts a bearer API token as well as OAuth; if it does not, drop the token path and keep OAuth only.

## Caching and rate limiting
- Cache: No local cache in the wrapped server. The `radar-au` skill keeps its own call budget and the briefing routine stores summaries in the intel store.
- Limiter: the wrapped server runs upstream, so the limit is enforced by a `tool_request` middleware budget in the `cyber-au` plugin keyed by server name (shared library `RateLimiter` semantics). Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/cloudflare-radar/tests/fixtures/tools_list_radar.json` (recorded tools/list, Radar subset)
- `mcp/cloudflare-radar/tests/fixtures/outages_AU.json`
- `mcp/cloudflare-radar/tests/fixtures/l7_summary_AU.json`
- `mcp/cloudflare-radar/tests/fixtures/bgp_hijacks.json`
- `mcp/cloudflare-radar/tests/fixtures/radar_429_with_retry_after.json`
- `mcp/cloudflare-radar/tests/fixtures/unauthorised_401.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- default state: a fresh install with the key present still renders `enabled: false`; an update keeps the user's `enabled: true`.
- Render test: with no token, the entry uses `auth: oauth`; with `CLOUDFLARE_RADAR_API_TOKEN` set, it uses the bearer header and no `auth` key; `tools.include` is exactly `["*_radar_*"]` in both.
- Filter test against the recorded `tools/list`: no tool outside `*_radar_*` registers, and every registered tool maps to a GET Radar endpoint.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `cloudflare-radar`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health cloudflare-radar --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/cloudflare-radar.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] Ships disabled (`enabled: false`) with the terms shown in docs, doctor and skill text; bootstrap and `hermes profile update` never enable it.
- [ ] No Cloudflare tool that can change an account is registered.
- [ ] Nothing depends on the deprecated dedicated Radar MCP server.

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
