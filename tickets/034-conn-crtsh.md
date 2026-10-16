---
key: "conn-crtsh"
title: "Connector: crt.sh certificate transparency (`crtsh`)"
labels: ["type:feature", "area:connectors", "priority:p2"]
milestone: "v0.2"
parent: "epic-connectors"
---
## Outcome
A read-only `crtsh` connector for crt.sh certificate transparency that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Useful for lookalike domain and phishing infrastructure checks. Dedupe by serial number.

Docs: https://crt.sh/

Verified on 16 October 2026: JSON query returned HTTP 200 on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://crt.sh/?q=<domain>&output=json | Certificates logged for a domain (use `%.` prefix for subdomains) |

- Auth: None.
- Rate limits: Shared public service that is often slow. One request every 5 seconds, 90 second timeout.
- Terms and attribution: Public CT data.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `crt.sh`

## Files
- `mcp/crtsh/src/cyberau_crtsh/source.py`
- `mcp/crtsh/schema/*.json`
- `mcp/crtsh/tests/test_crtsh.py`
- `mcp/crtsh/SOURCE.md`
- `docs/connectors/crtsh.md` (generated)

## Tools
### `crtsh_certs`
Certificates for a domain, deduplicated.

Model-facing name: `mcp__crtsh__crtsh_certs` (23 characters).

Input schema (`mcp/crtsh/schema/crtsh_certs.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "domain": {
      "type": "string",
      "format": "hostname"
    },
    "include_subdomains": {
      "type": "boolean",
      "default": true
    },
    "include_expired": {
      "type": "boolean",
      "default": false
    }
  },
  "required": [
    "domain"
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
  crtsh:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "crtsh"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: 24 hours per query.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/crtsh/tests/fixtures/crtsh_example.json`
- `mcp/crtsh/tests/fixtures/crtsh_timeout` (simulated)
- `mcp/crtsh/tests/fixtures/crtsh_502.html`

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `crtsh`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health crtsh --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/crtsh.md` generated and linked from the README table.
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
