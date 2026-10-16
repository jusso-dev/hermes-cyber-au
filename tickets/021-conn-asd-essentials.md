---
key: "conn-asd-essentials"
title: "Connector: Essential Eight and ASD Essentials (`e8`)"
labels: ["type:feature", "area:connectors", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
A read-only `e8` connector for Essential Eight and ASD Essentials that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
ASD launched the Essentials on 15 October 2026 and keeps the Essential Eight during a transition period. Support both. Essentials uses priority phases, not maturity levels, so the tool output must never present a phase as a maturity score. The OT chapter and the transition guide URLs must be confirmed on cyber.gov.au before the parser is written.

Docs: https://www.cyber.gov.au/publication/what-is-the-essentials

Verified on 16 October 2026: Launch notice and the enterprise IT and cloud chapter pages found on 16 October 2026. E8 ML baselines present in ISM OSCAL.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | ISM OSCAL `ISM_E8_ML1/2/3-baseline-resolved-profile_catalog.json` | Machine-readable Essential Eight maturity level baselines mapped to ISM controls |
| `GET` | https://www.cyber.gov.au/publication/what-is-the-essentials | ASD Essentials model: principles, actions, domains |
| `GET` | https://www.cyber.gov.au/publication/essentials-for-enterprise-it | Chapter: enterprise IT (evolution of the Essential Eight), eight domains in priority phases |
| `GET` | https://www.cyber.gov.au/publication/essentials-for-cloud | Chapter: SaaS and PaaS environments |
| `GET` | https://www.asd.gov.au/news/2026-10-15-asd-essentials-evolving-our-approach-cyber-security-resilience | Launch notice, 15 October 2026. Also names an OT chapter and transition guidance |

- Auth: None.
- Rate limits: Pages fetched only by the regeneration workflow, at most once a day, 1 request every 5 seconds.
- Terms and attribution: ASD content. Same attribution handling as the ASD connector.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `www.cyber.gov.au`, `www.asd.gov.au`, `raw.githubusercontent.com`

## Files
- `mcp/asd-essentials/src/cyberau_asd_essentials/source.py`
- `mcp/asd-essentials/schema/*.json`
- `mcp/asd-essentials/tests/test_asd_essentials.py`
- `mcp/asd-essentials/SOURCE.md`
- `docs/connectors/asd-essentials.md` (generated)

## Tools
### `e8_requirements`
Requirements for one Essential Eight mitigation strategy at a maturity level, with the mapped ISM control ids.

Model-facing name: `mcp__e8__e8_requirements` (24 characters).

Input schema (`mcp/asd-essentials/schema/e8_requirements.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "strategy": {
      "enum": [
        "patch_applications",
        "patch_operating_systems",
        "multi_factor_authentication",
        "restrict_admin_privileges",
        "application_control",
        "restrict_office_macros",
        "user_application_hardening",
        "regular_backups"
      ]
    },
    "maturity_level": {
      "type": "integer",
      "minimum": 1,
      "maximum": 3
    }
  },
  "required": [
    "strategy",
    "maturity_level"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `essentials_chapter`
Domains, principles, actions and priority phases for one ASD Essentials chapter.

Model-facing name: `mcp__e8__essentials_chapter` (27 characters).

Input schema (`mcp/asd-essentials/schema/essentials_chapter.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "chapter": {
      "enum": [
        "enterprise-it",
        "cloud",
        "ot"
      ]
    },
    "domain": {
      "type": "string"
    }
  },
  "required": [
    "chapter"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `essentials_transition`
How an Essential Eight strategy maps into the Essentials domains, quoted from ASD's transition guidance only.

Model-facing name: `mcp__e8__essentials_transition` (30 characters).

Input schema (`mcp/asd-essentials/schema/essentials_transition.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "strategy": {
      "type": "string"
    }
  },
  "required": [
    "strategy"
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
  e8:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "asd-essentials"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Shipped JSON snapshot `mcp/e8/data/essentials-<date>.json` and `mcp/e8/data/e8-maturity-<ism-release>.json`, each with source URL, retrieval date and SHA-256 of the source page.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/asd-essentials/tests/fixtures/essentials_enterprise_it.html`
- `mcp/asd-essentials/tests/fixtures/essentials_cloud.html`
- `mcp/asd-essentials/tests/fixtures/E8_ML2 resolved profile` (trimmed)
- `mcp/asd-essentials/tests/fixtures/page_layout_changed.html` (drift case)

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `asd-essentials`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health asd-essentials --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/asd-essentials.md` generated and linked from the README table.
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
