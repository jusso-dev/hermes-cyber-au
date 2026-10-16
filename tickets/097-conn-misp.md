---
key: "conn-misp"
title: "Connector: MISP via the official MISP MCP server, for your own instance or AusMISP (`misp`)"
labels: ["type:feature", "area:connectors", "priority:p3"]
milestone: "v1.0"
parent: "epic-connectors"
---
## Outcome
A pinned, read-only `misp` entry that wraps an existing MCP server for MISP via the official MISP MCP server, for your own instance or AusMISP, filtered to the tools listed below, with a skill that tells the agent how to use it, recorded-fixture tests and a live health probe.

## Context
Read-only first: search attributes, get an event, recent events. AusCERT members reach AusMISP through this connector. The upstream repository showed no detected licence; confirm before vendoring.

Docs: https://www.misp-project.org/

Verified on 16 October 2026: `MISP/misp-mcp` is public. Listed by a second inventory on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `MCP` | https://github.com/MISP/misp-mcp | Official MISP MCP server; pin a commit |
| `REST` | <your MISP instance> | Underlying API |

- Auth: The instance's API key, ideally a read-only key.
- Rate limits: Per instance.
- Terms and attribution: MISP software is AGPL-3.0; feed terms vary per feed. Respect TLP and sharing groups.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): (user supplied)

## Default state: off, bring your own key
Needs the user's own instance. Ships with `enabled: false`.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.misp` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/misp.md`, which quotes the terms.
- The skill text that uses it states the terms before the first call in a session.

## Files
- `mcp/misp/src/cyberau_misp/source.py`
- `mcp/misp/schema/*.json`
- `mcp/misp/tests/test_misp.py`
- `mcp/misp/SOURCE.md`
- `docs/connectors/misp.md` (generated)

## Tools
### (wrapped tools)
Search attributes, get one event with galaxies, recent events. Write tools excluded by `tools.include`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `MISP_URL` | yes | Instance URL. |
| `MISP_API_KEY` | yes | Read-only API key. |

## Hermes configuration
```yaml
mcp_servers:
  misp:
    command: "<PROFILE_HOME>/mcp/vendor/misp-mcp/<pinned launcher>"
    env:
      MISP_URL: "${MISP_URL}"
      MISP_API_KEY: "${MISP_API_KEY}"
    tools:
      include: ["<read tools frozen at build time>"]
    enabled: false
    lazy: true
    trust: untrusted
```

## Caching and rate limiting
- Cache: None beyond the intel store.
- Limiter: the wrapped server runs upstream, so the limit is enforced by a `tool_request` middleware budget in the `cyber-au` plugin keyed by server name (shared library `RateLimiter` semantics). Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/misp/tests/fixtures/event_three_attributes.json` (synthetic)
- `mcp/misp/tests/fixtures/search_no_hits.json`
- `mcp/misp/tests/fixtures/write_403.json`

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
- [ ] Contract suite passes for `misp`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health misp --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/misp.md` generated and linked from the README table.
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
