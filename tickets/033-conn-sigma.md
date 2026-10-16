---
key: "conn-sigma"
title: "Connector: SigmaHQ detection rules (`sigma`)"
labels: ["type:feature", "area:connectors", "priority:p1"]
milestone: "v0.2"
parent: "epic-connectors"
---
## Outcome
A read-only `sigma` connector for SigmaHQ detection rules that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Conversion uses pySigma with the Kusto backend for Microsoft Sentinel and Defender KQL. Check the current pySigma backend package names on PyPI before pinning.

Docs: https://github.com/SigmaHQ/sigma

Verified on 16 October 2026: SigmaHQ/sigma is public.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://api.github.com/repos/SigmaHQ/sigma/releases/latest | Release with rule packages (core, core+, emerging threats) |

- Auth: None. Optional `GITHUB_TOKEN`.
- Rate limits: GitHub API limits. One download per release.
- Terms and attribution: Sigma rules are under the Detection Rule License (DRL) 1.1, which requires attribution. Keep `author` and `id` on every rule shown.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.github.com`, `github.com`, `objects.githubusercontent.com`

## Files
- `mcp/sigma/src/cyberau_sigma/source.py`
- `mcp/sigma/schema/*.json`
- `mcp/sigma/tests/test_sigma.py`
- `mcp/sigma/SOURCE.md`
- `docs/connectors/sigma.md` (generated)

## Tools
### `sigma_search`
Search rules by keyword, ATT&CK technique, log source or level.

Model-facing name: `mcp__sigma__sigma_search` (24 characters).

Input schema (`mcp/sigma/schema/sigma_search.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "query": {
      "type": "string"
    },
    "technique_id": {
      "type": "string"
    },
    "product": {
      "type": "string"
    },
    "service": {
      "type": "string"
    },
    "level": {
      "enum": [
        "informational",
        "low",
        "medium",
        "high",
        "critical"
      ]
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 50,
      "default": 10
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `sigma_get`
One rule by id, as YAML.

Model-facing name: `mcp__sigma__sigma_get` (21 characters).

Input schema (`mcp/sigma/schema/sigma_get.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "rule_id": {
      "type": "string",
      "format": "uuid"
    }
  },
  "required": [
    "rule_id"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `sigma_convert`
Convert a stored rule or supplied YAML to a query language.

Model-facing name: `mcp__sigma__sigma_convert` (25 characters).

Input schema (`mcp/sigma/schema/sigma_convert.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "rule_id": {
      "type": "string"
    },
    "rule_yaml": {
      "type": "string",
      "maxLength": 20000
    },
    "target": {
      "enum": [
        "kusto",
        "splunk",
        "elasticsearch"
      ]
    }
  },
  "required": [
    "target"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | no | Optional, raises GitHub API limits. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  sigma:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "sigma"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      GITHUB_TOKEN: "${GITHUB_TOKEN}"
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Snapshot per release under `mcp/sigma/data/<tag>/`.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/sigma/tests/fixtures/release_latest.json`
- `mcp/sigma/tests/fixtures/rules_subset.zip` (10 rules)
- `mcp/sigma/tests/fixtures/rule_with_unsupported_modifier.yml`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `sigma`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health sigma --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/sigma.md` generated and linked from the README table.
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
