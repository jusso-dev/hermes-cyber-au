---
key: "conn-au-regulatory"
title: "Connector: Australian reporting obligations (OAIC NDB, SOCI, ransomware payments) (`aureg`)"
labels: ["type:feature", "area:connectors", "priority:p1"]
milestone: "v0.2"
parent: "epic-connectors"
---
## Outcome
A read-only `aureg` connector for Australian reporting obligations (OAIC NDB, SOCI, ransomware payments) that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe.

## Context
Verified rules to encode: NDB requires a reasonable assessment of a suspected eligible data breach within 30 days, then notification to affected individuals and the OAIC as soon as practicable. SOCI: critical incidents with significant impact on availability within 12 hours (written record within 84 hours of an oral report), other incidents with relevant impact within 72 hours (written record within 48 hours). The ransomware payment reporting rule must be confirmed from the Cyber Security Act 2024 text before it is encoded.

Docs: https://www.oaic.gov.au/privacy/notifiable-data-breaches

Verified on 16 October 2026: OAIC guidance pages, cyber.gov.au reporting page, CISC guidance PDF and SOCI s 30BC on AustLII reviewed via search on 16 October 2026.

## Source API
| Method | Endpoint | Notes |
|---|---|---|
| `GET` | https://www.oaic.gov.au/privacy/notifiable-data-breaches/quick-reference-guide-for-responding-to-data-breaches | OAIC quick reference |
| `GET` | https://www.oaic.gov.au/privacy/notifiable-data-breaches/preventing-preparing-for-and-responding-to-data-breaches/data-breach-preparation-and-response/part-4-notifiable-data-breach-ndb-scheme | OAIC NDB scheme detail |
| `GET` | https://www.cyber.gov.au/report-a-cyber-security-incident | SOCI Part 2B reporting to ASD's ACSC |
| `GET` | https://www.cisc.gov.au/resources-subsite/Documents/ncsi-guidance.pdf | CISC notification guidance |
| `GET` | https://www.legislation.gov.au/ | Primary legislation: Privacy Act 1988 Part IIIC, SOCI Act 2018 ss 30BC and 30BD, Cyber Security Act 2024 ransomware payment reporting (confirm section numbers on the register) |

- Auth: None.
- Rate limits: Fetched only by the regeneration workflow, once a week, 1 request every 5 seconds.
- Terms and attribution: Government content. Quote short passages with attribution. This is guidance, not legal advice, and every answer says so.
- Egress hosts (added to `mcp/egress-allowlist.yaml`): `www.oaic.gov.au`, `www.cyber.gov.au`, `www.cisc.gov.au`, `www.legislation.gov.au`

## Files
- `mcp/au-regulatory/src/cyberau_au_regulatory/source.py`
- `mcp/au-regulatory/schema/*.json`
- `mcp/au-regulatory/tests/test_au_regulatory.py`
- `mcp/au-regulatory/SOURCE.md`
- `docs/connectors/au-regulatory.md` (generated)

## Tools
### `aureg_obligation`
Return the encoded rule, deadline and quoted source text for a regime and trigger.

Model-facing name: `mcp__aureg__aureg_obligation` (28 characters).

Input schema (`mcp/au-regulatory/schema/aureg_obligation.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "regime": {
      "enum": [
        "ndb",
        "soci",
        "ransomware_payment"
      ]
    },
    "trigger": {
      "type": "string",
      "description": "For example 'critical_incident', 'other_incident', 'suspected_breach'"
    }
  },
  "required": [
    "regime"
  ]
}
```

Output: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.

### `aureg_deadline`
Compute deadlines in Australia/Sydney from an awareness time.

Model-facing name: `mcp__aureg__aureg_deadline` (26 characters).

Input schema (`mcp/au-regulatory/schema/aureg_deadline.input.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "regime": {
      "enum": [
        "ndb",
        "soci",
        "ransomware_payment"
      ]
    },
    "trigger": {
      "type": "string"
    },
    "aware_at": {
      "type": "string",
      "format": "date-time"
    }
  },
  "required": [
    "regime",
    "trigger",
    "aware_at"
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
  aureg:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "au-regulatory"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"

    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md), "Environment variable references"). The server gets no other environment.
## Caching and rate limiting
- Cache: Shipped snapshot `mcp/aureg/data/obligations-<date>.json`, each rule carrying the quoted source sentence, URL, retrieval date and SHA-256.
- Limiter: configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them.
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
- `mcp/au-regulatory/tests/fixtures/oaic_quick_ref.html`
- `mcp/au-regulatory/tests/fixtures/cyber_report_page.html`
- `mcp/au-regulatory/tests/fixtures/cisc_ncsi_guidance.pdf` (first pages)

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `au-regulatory`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health au-regulatory --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/au-regulatory.md` generated and linked from the README table.
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
