---
key: "conn-asd-ism"
title: "Connector: Information Security Manual (ISM) OSCAL catalogue (`ism`)"
labels: ["type:feature", "area:connectors", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A read-only `ism` connector for Information Security Manual (ISM) OSCAL catalogue that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Keep at least the two most recent releases so a question about a past date uses the release in force then. Control ids are normalised so `ISM-1173`, `1173` and the OSCAL id all resolve (check the exact OSCAL id format in `ISM_catalog.json` before writing the normaliser).

Docs: https://github.com/AustralianCyberSecurityCentre/ism-oscal

Verified on 16 October 2026: Repository is public, files listed via the GitHub contents API, releases `v2026.03.24`, `v2026.06.18`, `v2026.09.4` present.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://api.github.com/repos/AustralianCyberSecurityCentre/ism-oscal/releases | Release list. Latest seen: `v2026.09.4` (3 September 2026) |
| `GET` | https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal/<tag>/ISM_catalog.json | OSCAL catalog |
| `GET` | https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal/<tag>/ISM_<BASELINE>-baseline-resolved-profile_catalog.json | Resolved baselines: NON_CLASSIFIED, OFFICIAL_SENSITIVE, PROTECTED, SECRET, TOP_SECRET, E8_ML1, E8_ML2, E8_ML3 |

- Auth: None. Optional `GITHUB_TOKEN` raises the GitHub API limit from 60 to 5,000 requests an hour.
- Rate limits: GitHub API: 60 requests an hour unauthenticated. Raw downloads happen once per release.
- Terms and attribution: ISM content is published by ASD. Record the release tag, file SHA-256 and retrieval date for every answer.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.github.com`, `raw.githubusercontent.com`

## Files
- `mcp/asd-ism/src/cyberau_asd_ism/source.py`
- `mcp/asd-ism/schema/*.json`
- `mcp/asd-ism/tests/test_asd_ism.py`
- `mcp/asd-ism/SOURCE.md`
- `docs/connectors/asd-ism.md` (generated)

## Tools
### `ism_get_control`
Return one ISM control with statement, applicability, guideline and section, release tag and source hash.

Model-facing name: `mcp__ism__ism_get_control` (25 characters).

Input schema (`mcp/asd-ism/schema/ism_get_control.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "control_id": {
      "type": "string",
      "pattern": "^(ISM-)?\\d{3,4}$|^ism-"
    },
    "release": {
      "type": "string",
      "description": "Release tag. Default: latest in snapshot"
    }
  },
  "required": [
    "control_id"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `ism_search`
Full text search across controls, optionally limited to a baseline.

Model-facing name: `mcp__ism__ism_search` (20 characters).

Input schema (`mcp/asd-ism/schema/ism_search.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "query": {
      "type": "string",
      "minLength": 2
    },
    "baseline": {
      "enum": [
        "NON_CLASSIFIED",
        "OFFICIAL_SENSITIVE",
        "PROTECTED",
        "SECRET",
        "TOP_SECRET",
        "E8_ML1",
        "E8_ML2",
        "E8_ML3"
      ]
    },
    "release": {
      "type": "string"
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

### `ism_list_baseline`
List control ids in a baseline for a release.

Model-facing name: `mcp__ism__ism_list_baseline` (27 characters).

Input schema (`mcp/asd-ism/schema/ism_list_baseline.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "baseline": {
      "enum": [
        "NON_CLASSIFIED",
        "OFFICIAL_SENSITIVE",
        "PROTECTED",
        "SECRET",
        "TOP_SECRET",
        "E8_ML1",
        "E8_ML2",
        "E8_ML3"
      ]
    },
    "release": {
      "type": "string"
    }
  },
  "required": [
    "baseline"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `ism_diff`
Controls added, removed or changed between two releases.

Model-facing name: `mcp__ism__ism_diff` (18 characters).

Input schema (`mcp/asd-ism/schema/ism_diff.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "from_release": {
      "type": "string"
    },
    "to_release": {
      "type": "string"
    }
  },
  "required": [
    "from_release",
    "to_release"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | no | Optional. Read-only token for the GitHub releases API. |
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  ism:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "asd-ism"]
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
- Cache: Snapshot per release tag under `mcp/ism/data/<tag>/` (shipped, regenerated by the skill data workflow). Release list cached 12 hours.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/asd-ism/tests/fixtures/releases.json`
- `mcp/asd-ism/tests/fixtures/ISM_catalog.min.json` (trimmed to 20 controls)
- `mcp/asd-ism/tests/fixtures/E8_ML1 resolved profile` (trimmed)
- `mcp/asd-ism/tests/fixtures/github_403_rate_limited.json`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `asd-ism`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health asd-ism --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/asd-ism.md` generated and linked from the README table.
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
