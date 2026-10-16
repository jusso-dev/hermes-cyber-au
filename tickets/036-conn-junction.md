---
key: "conn-junction"
title: "Connector: Junction (Microsoft Graph, Defender, Sentinel) (`junction`)"
labels: ["type:feature", "area:connectors", "priority:p2"]
milestone: "v0.2"
parent: "epic-connectors"
---
## Outcome
A read-only `junction` connector for Junction (Microsoft Graph, Defender, Sentinel) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Integration only: ship a disabled `mcp_servers.junction` entry with `trust: untrusted` and a `tools.include` list limited to read operations used by the skills (Sentinel query, Defender incidents list, sign-in logs). Copy the exact MCP launch command from Junction's README at implementation time.

Docs: https://github.com/jusso-dev/junction

Verified on 16 October 2026: jusso-dev/junction is public; README describes CLI, MCP and local HTTP API.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `MCP` | Junction's own MCP server | Microsoft Graph, Entra, Intune, Defender and Sentinel operations from Microsoft's published specs |

- Auth: Microsoft Entra sign-in handled by Junction (see its README). No Microsoft secret lives in this repo.
- Rate limits: Microsoft Graph and ARM throttling, handled by Junction.
- Terms and attribution: Junction is MIT and not affiliated with Microsoft. Microsoft API terms apply.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `graph.microsoft.com`, `management.azure.com`, `api.loganalytics.io`, `login.microsoftonline.com`

## Files
- `mcp/servers.yaml` (junction entry, disabled by default)
- `skills/threat-hunting/references/junction.md`
- `tests/integration/test_junction_tools_list.py`
- `docs/connectors/junction.md`

## Tools
### (Junction tools)
Use Junction's own tool names; filter with `tools.include`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `JUNCTION_BIN` | no | Path to the junction binary if it is not on PATH. |

## Hermes configuration
```yaml
mcp_servers:
  junction:
    command: "${JUNCTION_BIN}"      # copy the real MCP launch args from Junction's README
    args: ["mcp"]                   # placeholder: verify
    enabled: false
    trust: untrusted
    tools:
      include: ["<read-only operation tools used by skills>"]
```
Use `trust: untrusted` so any tool without `readOnlyHint: true` asks first, and fails closed in cron.

## Caching and rate limiting
- Cache: None in this repo. Junction manages its own.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/junction/tests/fixtures/recorded MCP tools/list response from a pinned Junction release`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `junction`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health junction --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/junction.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).

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
