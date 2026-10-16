---
key: "conn-m365-secure"
title: "Integration: M365-Secure assessment reports"
labels: ["type:feature", "area:connectors", "priority:p2"]
milestone: "v0.2"
parent: "epic-connectors"
---
## Outcome
A read-only `(none)` connector for M365-Secure assessment reports that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Not an MCP server. A parser in `plugins/cyber-au/evidence/m365_secure.py` reads the JSON report so the Essential Eight and Essentials skill can use it as evidence. Confirm the report schema from the tool's source.

Docs: https://github.com/jusso-dev/M365-Secure

Verified on 16 October 2026: jusso-dev/M365-Secure is public; README documents HTML, CSV and JSON reports.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `File` | JSON report written by `m365-assess` | Microsoft 365 configuration findings with framework references |

- Auth: None in this repo. The user runs M365-Secure themselves.
- Rate limits: Not applicable.
- Terms and attribution: M365-Secure's own licence.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): none

## Files
- `plugins/cyber-au/evidence/m365_secure.py`
- `plugins/cyber-au/evidence/schema/m365_secure_report.schema.json`
- `tests/plugin/test_evidence_m365_secure.py`
- `docs/connectors/m365-secure.md`

## Tools
### `evidence_import`
Import an M365-Secure JSON report as assessment evidence (plugin tool).

Registered by the `cyber-au` plugin, not an MCP server.

Input schema (`mcp/m365-secure/schema/evidence_import.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "path": {
      "type": "string"
    }
  },
  "required": [
    "path"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| (none) | | |

## Caching and rate limiting
- Cache: Not applicable.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/m365-secure/tests/fixtures/m365_secure_report_sample.json` (synthetic)

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `m365-secure`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health m365-secure --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/m365-secure.md` generated and linked from the README table.
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
