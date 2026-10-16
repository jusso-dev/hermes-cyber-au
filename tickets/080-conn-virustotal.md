---
key: "conn-virustotal"
title: "Connector: VirusTotal via the official VirusTotal MCP server (`virustotal`)"
labels: ["type:feature", "area:connectors", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A pinned, read-only `virustotal` entry that wraps an existing MCP server for VirusTotal via the official VirusTotal MCP server, filtered to the tools listed below, with a skill that tells the agent how to use it, recorded-fixture tests and a live health probe.

## Context
Zero-build quick win for v0.1: wrap the official server rather than writing a client. Reports only. Upload, rescan, comment and vote tools are excluded by `tools.include`. Confirm exact tool names from the pinned release, then freeze them in `mcp/virustotal/expected_tools.txt`.

Docs: https://docs.virustotal.com/reference/overview

Verified on 16 October 2026: `/api/v3/ip_addresses/8.8.8.8` returned 401 without a key from the build box on 16 October 2026. Repository `VirusTotal/virustotal-mcp` is public. Listed by a second inventory on 16 October 2026, which also read the Public API limits and terms.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `MCP` | https://github.com/VirusTotal/virustotal-mcp | Official VirusTotal MCP server, run locally over stdio. Pin a release or commit |
| `GET` | https://www.virustotal.com/api/v3/files/{hash} , /urls/{id} , /domains/{domain} , /ip_addresses/{ip} | Underlying API v3 reports |

- Auth: `x-apikey` header with the user's own VirusTotal key.
- Rate limits: Public API: 4 requests a minute and 500 a day. Premium keys have their own quota.
- Terms and attribution: The VirusTotal Public API must not be used in commercial products or services, or in business workflows that do not contribute new files. Premium API is paid. Show this in the skill text and docs.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `www.virustotal.com`

## Default state: off, bring your own key
VirusTotal Public API terms rule out commercial use (see Terms). The server ships with `enabled: false` and users bring their own key, Public or Premium.

- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.virustotal` even when the key is set (`enabled` is a documented per-server field).
- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.
- `doctor` lists it as "off by default: licence terms" with a link to `docs/connectors/virustotal.md`, which quotes the terms.
- The skill text that uses it states the terms before the first call in a session.

## Files
- `mcp/servers.yaml` (entry `virustotal`, wrap)
- `mcp/vendor/virustotal-mcp.lock` (pinned version and checksum)
- `mcp/virustotal/expected_tools.txt`
- `mcp/virustotal/tests/test_virustotal_wrap.py`
- `mcp/virustotal/SOURCE.md`
- `docs/connectors/virustotal.md` (generated)

## Tools
### (wrapped tools)
Report lookups only: file by hash, URL, domain and IP. Each answer carries detection counts, first and last analysis dates and a permalink. Upload, rescan and community write tools stay excluded.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | yes | The user's own VirusTotal API key. Never shared or shipped. |

## Hermes configuration
```yaml
mcp_servers:
  virustotal:
    command: "<PROFILE_HOME>/mcp/vendor/virustotal-mcp/<pinned launcher>"   # set from the pinned release's README
    env:
      VIRUSTOTAL_API_KEY: "${VIRUSTOTAL_API_KEY}"
    tools:
      include: ["<file report tool>", "<url report tool>", "<domain report tool>", "<ip report tool>"]   # exact names frozen at build time
    enabled: false        # Public API terms are non-commercial; the user switches it on
    lazy: true
    timeout: 60
    trust: untrusted
```
Field names from [`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md). Stdio servers get a filtered environment, so the key must be passed through `env`.

## Caching and rate limiting
- Cache: Reports cached 24 hours in the plugin middleware, keyed by indicator, so repeat questions do not spend quota.
- Limiter: the wrapped server runs upstream, so the limit is enforced by a `tool_request` middleware budget in the `cyber-au` plugin keyed by server name (shared library `RateLimiter` semantics). Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/virustotal/tests/fixtures/file_report_known_bad.json`
- `mcp/virustotal/tests/fixtures/domain_report_clean.json`
- `mcp/virustotal/tests/fixtures/vt_401.json`
- `mcp/virustotal/tests/fixtures/vt_429_quota.json`
- `mcp/virustotal/tests/fixtures/tools_list.json` (recorded tools/list)

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- default state: a fresh install with the key present still renders `enabled: false`; an update keeps the user's `enabled: true`.
- Filter test: against the recorded `tools/list`, only the four report tools register.
- Quota test: the middleware budget refuses the fifth call inside a minute with a clear message, before the upstream 429.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `virustotal`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health virustotal --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/virustotal.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] Ships disabled (`enabled: false`) with the terms shown in docs, doctor and skill text; bootstrap and `hermes profile update` never enable it.
- [ ] No upload, rescan, comment or vote tool is registered.

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
