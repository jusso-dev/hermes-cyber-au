---
key: "conn-hibp"
title: "Connector: Have I Been Pwned via the official HIBP MCP server (`hibp`)"
labels: ["type:feature", "area:connectors", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A pinned, read-only `hibp` entry that wraps an existing MCP server for Have I Been Pwned via the official HIBP MCP server, filtered to the tools listed below, with a skill that tells the agent how to use it, recorded-fixture tests and a live health probe.

## Context
Zero-build quick win for v0.1, run by an Australian. Public tools work without sign-in. Account and domain lookups touch personal information, so they need a human approval in the `pre_tool_call` guard and results are never written to the intel store. Passwords are never sent: only the 5 character SHA-1 prefix leaves the machine.

Docs: https://haveibeenpwned.com/API/v3

Verified on 16 October 2026: `/api/v3/breaches` returned 200 and `https://haveibeenpwned.com/mcp` returned 406 to a plain GET (exists) from the build box on 16 October 2026. Listed by a second inventory on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `MCP` | https://haveibeenpwned.com/mcp | Official remote MCP server, documented at https://haveibeenpwned.com/Docs/MCP |
| `GET` | https://haveibeenpwned.com/api/v3/breaches | All breach metadata, no key |
| `GET` | https://api.pwnedpasswords.com/range/{first 5 SHA-1 hex} | Pwned Passwords k-anonymity range, no key |
| `GET` | https://haveibeenpwned.com/api/v3/breachedaccount/{account} | Breaches for an email address, paid key or OAuth with a subscription |

- Auth: None for breach metadata and Pwned Passwords. Email and domain searches, pastes and stealer logs need a paid key or OAuth to an HIBP account with the right subscription.
- Rate limits: Depends on the key. A 429 carries `retry-after`; honour it.
- Terms and attribution: Breach data is CC BY 4.0 with attribution to Have I Been Pwned. No licence or attribution requirement on Pwned Passwords. Do not misrepresent the data source.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `haveibeenpwned.com`, `api.pwnedpasswords.com`

## Files
- `mcp/servers.yaml` (entry `hibp`, wrap)
- `mcp/hibp/expected_tools.txt`
- `mcp/hibp/tests/test_hibp_wrap.py`
- `mcp/hibp/SOURCE.md`
- `docs/connectors/hibp.md` (generated)

## Tools
### (wrapped tools)
Public: list breaches (optionally by domain), get one breach, Pwned Passwords range lookup. Subscription: breached account, breached domain. Confirm names against the server and freeze them.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `HIBP_API_KEY` | no | Optional paid key for account and domain searches. Without it only public tools work. |

## Hermes configuration
```yaml
mcp_servers:
  hibp:
    url: "https://haveibeenpwned.com/mcp"
    # headers rendered only when HIBP_API_KEY is set; confirm the header name in the HIBP MCP docs at build time
    # headers:
    #   hibp-api-key: "${HIBP_API_KEY}"
    enabled: true
    lazy: true
    timeout: 60
    trust: untrusted
```
Field names from [`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md).

## Caching and rate limiting
- Cache: Breach list 24 hours. Account and domain results are not cached on disk (they are personal information).
- Limiter: the wrapped server runs upstream, so the limit is enforced by a `tool_request` middleware budget in the `cyber-au` plugin keyed by server name (shared library `RateLimiter` semantics). Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/hibp/tests/fixtures/breaches.json`
- `mcp/hibp/tests/fixtures/range_21BD1.txt`
- `mcp/hibp/tests/fixtures/hibp_401.json`
- `mcp/hibp/tests/fixtures/account-exists` (HIBP published test account on hibp-integration-tests.com)
- `mcp/hibp/tests/fixtures/multiple-breaches` (published test account)

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.
- Approval test: an account or domain lookup without an approval token is blocked by the guard and logged.
- Privacy test: no email address appears in the intel store, cache or audit log body (hashes only).

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `hibp`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health hibp --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/hibp.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).
- [ ] Account and domain lookups require human approval and are never stored.
- [ ] Only HIBP's published test accounts are used in tests.

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
