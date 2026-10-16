---
key: "premium-interface"
title: "Design: common premium-connector interface (licence keys, terms flags, quota guardrails, exposure records, privacy)"
labels: ["type:feature", "area:connectors", "area:premium-feeds", "area:security", "priority:p1"]
milestone: "v0.2"
parent: "epic-premium"
---
## Outcome
One interface every premium connector implements, so paid feeds are off until the user brings a licence, cannot spend more than the user allows, never cache or export what the licence forbids, and land in the intel store as one normalised `exposures` record type.

## Context
Paid feeds on Australian organisations (dark web, leak sites, infostealer and breach exposure, brand and attack surface) carry licence terms and personal information that free feeds do not. The vendor tickets under this epic only fill in endpoints and tools; everything below is shared and lives in one place.

## Files
- `mcp/premium/src/cyberau_premium/base.py`: `PremiumConnector` base class, `TermsProfile`, `QuotaPolicy`, `ExposureFinding`
- `mcp/premium/src/cyberau_premium/budget.py`: quota and cost ledger
- `mcp/premium/src/cyberau_premium/redact.py`: credential and personal information redaction
- `mcp/premium/vendors.yaml`: per-vendor terms flags, quota defaults, licence env name
- `mcp/premium/schema/exposure_finding.json`
- `plugins/cyber-au/hooks/premium_guard.py`: `pre_tool_call` guard (budget, terms, approval)
- `docs/premium/README.md` and `docs/premium/terms/<vendor>.md` (generated from `vendors.yaml`)
- `mcp/premium/tests/` (contract suite every vendor must pass)

## Interface
```python
class TermsProfile(BaseModel):
    cache: Literal["none", "session", "ttl"]        # session = memory only, cleared at session end
    cache_ttl_max_s: int = 0
    store: Literal["none", "metadata", "full"]      # what may go into the intel store
    stix_export: bool = False                       # may findings leave the profile as STIX
    share_outside_profile: bool = False             # briefings to channels other than the owner's
    redistribution: Literal["forbidden", "internal", "allowed"] = "forbidden"
    attribution: str

class QuotaPolicy(BaseModel):
    calls_per_day: int | None
    calls_per_month: int | None
    cost_units_per_call: float = 1.0
    monthly_budget_units: float | None              # user-set; None = vendor quota only
    approval_above_units: float | None              # ask the user before a call that costs more
    hard_stop: bool = True

class PremiumConnector(Connector):                  # Connector from the shared library ticket
    vendor: str
    licence_env: tuple[str, ...]                    # names only; values come from the profile .env
    terms: TermsProfile
    quota: QuotaPolicy
    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]: ...
    def health(self) -> HealthResult: ...           # one cheap authenticated call, no quota-heavy endpoints
```

## Licence key placeholder and default state
- Each vendor entry in `mcp/servers.yaml` has `default_enabled: false`, `paid: true` and env placeholders such as `HUDSONROCK_API_KEY: "${HUDSONROCK_API_KEY}"` resolved from the profile `.env` ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md)). `.env.template` lists them commented out with "paid, bring your own licence".
- Bootstrap renders `enabled: false` even when the key is present. The user enables a vendor by setting `enabled: true` in their own `config.yaml`, which `hermes profile update` keeps.
- `doctor` prints each premium vendor as `off (paid, bring your own licence)`, `on`, or `on, key missing`.

## Terms and redistribution flags
- `vendors.yaml` holds the conservative defaults from each vendor ticket. The user can relax a flag in `config.yaml` under `cyber_au.premium.<vendor>.terms` only by also setting `contract_ref` (free text, for example a contract number), which is written to the audit log.
- Enforcement points: the shared HTTP cache refuses to persist responses when `cache` is `none` or `session`; the store writer drops fields beyond `store`; STIX export skips findings with `stix_exportable: false` and says how many it skipped; the briefing renderer drops findings with `share_outside_profile: false` from any delivery target other than the owner's.

## Quota and cost guardrails
- `budget.py` keeps a ledger in `plugin-data/cyber-au/premium-ledger.sqlite` (per vendor: calls, cost units, month in Australia/Sydney).
- `premium_guard.py` runs as `pre_tool_call` and blocks a call that would pass `calls_per_day`, `calls_per_month` or `monthly_budget_units`, with a message naming the limit. Above `approval_above_units` it asks for approval first.
- Bulk tools page at most `max_pages` (default 5) per call. Cron routines get their own smaller budget share (default 50 per cent).
- `doctor --premium` shows usage against limits.

## Normalisation into the intel store
New table, created by the store migration:
```sql
CREATE TABLE IF NOT EXISTS exposures (
  finding_id      TEXT PRIMARY KEY,
  vendor          TEXT NOT NULL,
  kind            TEXT NOT NULL,
  subject_type    TEXT NOT NULL,
  subject_value   TEXT NOT NULL,
  watchlist_entry TEXT,
  counts_json     TEXT,
  data_classes    TEXT,
  first_seen      TEXT,
  observed_at     TEXT NOT NULL,
  source_ref      TEXT,
  confidence      TEXT NOT NULL,
  licence_scope   TEXT NOT NULL,
  stix_exportable INTEGER NOT NULL DEFAULT 0,
  has_pi          INTEGER NOT NULL DEFAULT 0,
  expires_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS exposures_subject ON exposures(subject_type, subject_value);
```
Dedupe on `finding_id`; a repeat updates `observed_at` and counts. `expires_at` defaults to 90 days and the retention job deletes expired rows.

`ExposureFinding` JSON schema (`mcp/premium/schema/exposure_finding.json`):
```json
{
  "type": "object",
  "additionalProperties": false,
  "required": [
    "finding_id",
    "vendor",
    "kind",
    "subject",
    "observed_at",
    "licence_scope",
    "confidence"
  ],
  "properties": {
    "finding_id": {
      "type": "string",
      "description": "sha256(vendor|kind|subject.value|source_ref)"
    },
    "vendor": {
      "type": "string"
    },
    "kind": {
      "enum": [
        "infostealer_credential",
        "breach_credential",
        "leak_site_claim",
        "data_leak_disclosure",
        "dark_web_mention",
        "typosquat_domain",
        "brand_impersonation",
        "attack_surface_issue"
      ]
    },
    "subject": {
      "type": "object",
      "required": [
        "type",
        "value"
      ],
      "properties": {
        "type": {
          "enum": [
            "domain",
            "abn",
            "brand",
            "email_domain",
            "ip"
          ]
        },
        "value": {
          "type": "string"
        },
        "watchlist_entry": {
          "type": "string",
          "description": "id of the matching watchlist entry, if any"
        }
      }
    },
    "counts": {
      "type": "object",
      "description": "for example employees, users, third_parties, records",
      "additionalProperties": {
        "type": "integer"
      }
    },
    "data_classes": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "first_seen": {
      "type": "string",
      "format": "date-time"
    },
    "observed_at": {
      "type": "string",
      "format": "date-time"
    },
    "source_ref": {
      "type": "string",
      "description": "vendor record id or permalink; never the leaked content"
    },
    "confidence": {
      "enum": [
        "vendor_confirmed",
        "vendor_reported",
        "unverified_claim"
      ]
    },
    "licence_scope": {
      "enum": [
        "session_only",
        "store_metadata",
        "store_full"
      ]
    },
    "stix_exportable": {
      "type": "boolean"
    },
    "contains_personal_information": {
      "type": "boolean"
    }
  }
}
```

## Privacy and handling of victim and breach data
- Exposure data often contains personal information about staff or customers. Treat it under the Australian Privacy Principles: collect only what the task needs (APP 3), use it only for the security purpose it was collected for (APP 6), take reasonable steps to protect it and destroy it when no longer needed (APP 11). Most vendors are overseas, so query parameters sent to them are a cross-border disclosure to consider under APP 8. This is guidance for the operator, not legal advice.
- Never store or display plaintext passwords, session cookies or tokens. `redact.py` replaces them with a type and a short hash before anything leaves the connector.
- Leak site claims are allegations made by criminals. Label them `unverified_claim`. Never download leaked files or follow leak site links.
- Third party victims: findings about organisations not on the user's watchlist are not stored and not mentioned in briefings unless the user asks.
- No auto-notification. Nothing in this distribution contacts the OAIC, ASD, affected individuals, the victim organisation or a vendor. Skills can draft, and a person sends.
- A finding about the user's own organisation may start the clock for assessing a suspected eligible data breach under the NDB scheme; the skills say so and hand off to the breach notification skill.

## Tests
- Contract suite: every premium connector passes `test_off_by_default`, `test_no_key_reports_not_configured`, `test_terms_cache_none_never_hits_disk`, `test_store_metadata_drops_values`, `test_stix_skips_non_exportable`, `test_budget_blocks_over_limit`, `test_redaction` (passwords, cookies, tokens, emails in free text), `test_findings_match_schema`.
- Fixtures are synthetic. A CI check rejects any fixture containing an email address outside `example.com`, `example.com.au` or `example.au`, or a domain that resolves.

## Acceptance criteria
- [ ] Interface and contract suite merged; at least one v0.2 vendor passes it.
- [ ] Fresh install with all premium keys set: every premium server renders `enabled: false`.
- [ ] Budget guard blocks the call after the limit and logs it.
- [ ] STIX export of a store with non-exportable findings exports none of them and reports the count.
- [ ] `docs/premium/README.md` explains terms flags, budgets and the privacy note in plain language.

## Constraints
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`).
- Never commit real victim, breach or credential data, including in fixtures or screenshots.

## Out of scope
Buying licences, vendor onboarding, and any write call to a vendor (creating watchers, rules or takedown requests).

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
