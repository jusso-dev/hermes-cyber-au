---
key: "conn-mitre-attack"
title: "Connector: MITRE ATT&CK (STIX 2.1) (`attack`)"
labels: ["type:feature", "area:connectors", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A read-only `attack` connector for MITRE ATT&CK (STIX 2.1) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Store technique id, name, tactic, platforms, data sources, detections and mitigations. Skip revoked and deprecated objects by default.

Docs: https://github.com/mitre-attack/attack-stix-data

Verified on 16 October 2026: `index.json` returned HTTP 200 on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json | Collection index with versions |
| `GET` | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json | Enterprise STIX 2.1 bundle (also mobile and ics) |

- Auth: None.
- Rate limits: Downloaded only when `index.json` reports a new version.
- Terms and attribution: ATT&CK terms of use require attribution to MITRE.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `raw.githubusercontent.com`

## Files
- `mcp/mitre-attack/src/cyberau_mitre_attack/source.py`
- `mcp/mitre-attack/schema/*.json`
- `mcp/mitre-attack/tests/test_mitre_attack.py`
- `mcp/mitre-attack/SOURCE.md`
- `docs/connectors/mitre-attack.md` (generated)

## Tools
### `attack_technique`
One technique or sub-technique by id, with tactics, mitigations and detection notes.

Model-facing name: `mcp__attack__attack_technique` (29 characters).

Input schema (`mcp/mitre-attack/schema/attack_technique.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "technique_id": {
      "type": "string",
      "pattern": "^T\\d{4}(\\.\\d{3})?$"
    }
  },
  "required": [
    "technique_id"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `attack_search`
Search techniques, groups and software by keyword.

Model-facing name: `mcp__attack__attack_search` (26 characters).

Input schema (`mcp/mitre-attack/schema/attack_search.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "query": {
      "type": "string"
    },
    "domain": {
      "enum": [
        "enterprise",
        "mobile",
        "ics"
      ],
      "default": "enterprise"
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 50,
      "default": 10
    }
  },
  "required": [
    "query"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `attack_group`
One threat group with aliases and associated techniques.

Model-facing name: `mcp__attack__attack_group` (25 characters).

Input schema (`mcp/mitre-attack/schema/attack_group.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "name_or_id": {
      "type": "string"
    }
  },
  "required": [
    "name_or_id"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| (none) | | |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  attack:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "mitre-attack"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Snapshot per ATT&CK version under `mcp/attack/data/<version>/` (indexed into SQLite at bootstrap).
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/mitre-attack/tests/fixtures/index.json`
- `mcp/mitre-attack/tests/fixtures/enterprise-attack.min.json` (trimmed bundle)

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `mitre-attack`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health mitre-attack --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/mitre-attack.md` generated and linked from the README table.
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
