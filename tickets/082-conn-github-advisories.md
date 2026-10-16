---
key: "conn-github-advisories"
title: "Connector: GitHub Advisory Database via the GitHub MCP server (`ghsa`)"
labels: ["type:feature", "area:connectors", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A pinned, read-only `ghsa` entry that wraps an existing MCP server for GitHub Advisory Database via the GitHub MCP server, filtered to the tools listed below, with a skill that tells the agent how to use it, recorded-fixture tests and a live health probe.

## Context
Zero-build quick win for v0.1. Enable only the read-only `security_advisories` toolset (`get_global_security_advisory`, `list_global_security_advisories`), never repository, issue or pull request tools. Complements OSV for package-level answers and NVD for CVSS.

Docs: https://github.com/advisories

Verified on 16 October 2026: `/advisories?per_page=1` returned 200 unauthenticated from the build box on 16 October 2026. `github/github-mcp-server` is public. Listed by a second inventory on 16 October 2026, which read the toolset names in the server README.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `MCP` | https://github.com/github/github-mcp-server | Official GitHub MCP server with the `security_advisories` toolset only |
| `GET` | https://api.github.com/advisories | Underlying REST endpoint for global advisories |

- Auth: Works unauthenticated at low volume. A fine-grained token with no repository access raises limits.
- Rate limits: GitHub REST limits: 60 requests an hour unauthenticated, 5,000 with a token.
- Terms and attribution: Advisory data is CC BY 4.0. Attribute the GitHub Advisory Database.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `api.github.com`

## Files
- `mcp/servers.yaml` (entry `ghsa`, wrap)
- `mcp/vendor/github-mcp-server.lock`
- `mcp/github-advisories/tests/test_ghsa_wrap.py`
- `mcp/github-advisories/SOURCE.md`
- `docs/connectors/github-advisories.md` (generated)

## Tools
### `list_global_security_advisories`
Filter by ecosystem, affected package, severity, CVE or GHSA id (upstream tool).

Model-facing name: `mcp__ghsa__list_global_security_advisories` (42 characters).

Input schema (`mcp/github-advisories/schema/list_global_security_advisories.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "ecosystem": {
      "type": "string"
    },
    "affects": {
      "type": "string"
    },
    "severity": {
      "enum": [
        "low",
        "medium",
        "high",
        "critical"
      ]
    },
    "cve_id": {
      "type": "string",
      "pattern": "^CVE-\\d{4}-\\d{4,}$"
    }
  },
  "required": []
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `get_global_security_advisory`
One advisory by GHSA id (upstream tool).

Model-facing name: `mcp__ghsa__get_global_security_advisory` (39 characters).

Input schema (`mcp/github-advisories/schema/get_global_security_advisory.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "ghsaId": {
      "type": "string",
      "pattern": "^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$"
    }
  },
  "required": [
    "ghsaId"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `GITHUB_ADVISORY_TOKEN` | no | Optional fine-grained token with no repository permissions, used only for rate limits. |

## Hermes configuration
```yaml
mcp_servers:
  ghsa:
    command: "<PROFILE_HOME>/mcp/vendor/github-mcp-server/<pinned binary>"
    args: ["stdio", "--toolsets", "security_advisories", "--read-only"]   # confirm flag names in the pinned release
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_ADVISORY_TOKEN}"
    tools:
      include: ["get_global_security_advisory", "list_global_security_advisories"]
    enabled: true
    lazy: true
    timeout: 60
    trust: untrusted
```
Field names from [`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md). The `tools.include` list is the backstop if a flag changes upstream.

## Caching and rate limiting
- Cache: Advisory pages 6 hours in the plugin middleware.
- Limiter: the wrapped server runs upstream, so the limit is enforced by a `tool_request` middleware budget in the `cyber-au` plugin keyed by server name (shared library `RateLimiter` semantics). Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/github-advisories/tests/fixtures/advisories_page.json`
- `mcp/github-advisories/tests/fixtures/advisory_withdrawn.json`
- `mcp/github-advisories/tests/fixtures/tools_list.json` (recorded tools/list)

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- Filter test: no tool outside the two advisory tools registers, even if the toolset flag is ignored.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `github-advisories`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health github-advisories --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/github-advisories.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] The token, if set, has no repository permissions (documented, and doctor warns if the token can read a repository).

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
