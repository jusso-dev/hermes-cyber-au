"""Premium and commercial intel feeds: epic children (interface, skill and routine, wiring, vendors)."""
from __future__ import annotations

from common import M_V02, M_V10, COMMON_CONSTRAINTS, hsrc, dedent
from t_connectors import connector_ticket
from common import schema_block
from inventory import obj, S
from inventory_premium import PREMIUM

E = "epic-premium"
AREA = "area:premium-feeds"

FINDING_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["finding_id", "vendor", "kind", "subject", "observed_at", "licence_scope", "confidence"],
    "properties": {
        "finding_id": {"type": S, "description": "sha256(vendor|kind|subject.value|source_ref)"},
        "vendor": {"type": S},
        "kind": {"enum": ["infostealer_credential", "breach_credential", "leak_site_claim", "data_leak_disclosure", "dark_web_mention", "typosquat_domain", "brand_impersonation", "attack_surface_issue"]},
        "subject": {"type": "object", "required": ["type", "value"], "properties": {
            "type": {"enum": ["domain", "abn", "brand", "email_domain", "ip"]},
            "value": {"type": S},
            "watchlist_entry": {"type": S, "description": "id of the matching watchlist entry, if any"}}},
        "counts": {"type": "object", "description": "for example employees, users, third_parties, records", "additionalProperties": {"type": "integer"}},
        "data_classes": {"type": "array", "items": {"type": S}},
        "first_seen": {"type": S, "format": "date-time"},
        "observed_at": {"type": S, "format": "date-time"},
        "source_ref": {"type": S, "description": "vendor record id or permalink; never the leaked content"},
        "confidence": {"enum": ["vendor_confirmed", "vendor_reported", "unverified_claim"]},
        "licence_scope": {"enum": ["session_only", "store_metadata", "store_full"]},
        "stix_exportable": {"type": "boolean"},
        "contains_personal_information": {"type": "boolean"},
    },
}

WATCHLIST_YAML = """```yaml
# <profile>/watchlists/org-exposure.yaml  (user-owned; never shipped, never committed)
organisation: "Example Pty Ltd"
abns:
  - "51 824 753 556"          # checksum validated; example ABN from the ATO's published algorithm notes, replace
domains:
  - example.com.au
  - example.au
email_domains:
  - example.com.au
brands:
  - "Example"
  - "ExampleCo"
subsidiaries:
  - name: "Example Services Pty Ltd"
    domains: [exampleservices.com.au]
exclude:
  - "example.com"            # avoid false positives on generic names
alert:
  min_confidence: vendor_reported
  kinds: [infostealer_credential, breach_credential, leak_site_claim, data_leak_disclosure, typosquat_domain]
```"""


def interface_ticket():
    body = dedent(f"""
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
- Each vendor entry in `mcp/servers.yaml` has `default_enabled: false`, `paid: true` and env placeholders such as `HUDSONROCK_API_KEY: "${{HUDSONROCK_API_KEY}}"` resolved from the profile `.env` ({hsrc('website/docs/reference/mcp-config-reference.md')}). `.env.template` lists them commented out with "paid, bring your own licence".
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
{schema_block(FINDING_SCHEMA)}

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
{COMMON_CONSTRAINTS}
- Never commit real victim, breach or credential data, including in fixtures or screenshots.

## Out of scope
Buying licences, vendor onboarding, and any write call to a vendor (creating watchers, rules or takedown requests).
""")
    return dict(key="premium-interface", parent=E, milestone=M_V02,
                labels=["type:feature", "area:connectors", AREA, "area:security", "priority:p1"],
                title="Design: common premium-connector interface (licence keys, terms flags, quota guardrails, exposure records, privacy)",
                body=body)


def skill_ticket():
    tool_schema = obj({"subject": {"type": S, "description": "domain, ABN, brand or watchlist entry id; default all watchlist entries"},
                       "since": {"type": S, "format": "date"}, "kinds": {"type": "array", "items": {"type": S}},
                       "vendors": {"type": "array", "items": {"type": S}}})
    body = dedent(f"""
## Outcome
An `au-org-exposure` skill that answers "is my organisation exposed?" from every enabled premium feed and the free ransomware tracker, plus a paused routine that alerts the owner when a new finding matches their own domains, ABNs or brands.

## Watchlist
User-owned file, created by `cyberau watchlist init --org`, validated on load, never shipped:
{WATCHLIST_YAML}
- ABNs are validated with the ATO checksum (subtract 1 from the first digit, weights 10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, sum divisible by 89). Replace the example before use. Vendors search by name and domain, so an ABN expands to the entity's registered and business names through ABN Lookup web services (free GUID registration; confirm the endpoint at build time) and only those names are sent.
- Shares the brand and domain lists with {{{{ref:routine-watchlists}}}} so the user keeps one list.

## Skill: `skills/au-org-exposure/SKILL.md`
Frontmatter `metadata.hermes.related_skills: [incident-triage, ndb-breach-notification, executive-briefing]`.
Procedure:
1. Load the watchlist; refuse to search for names that are not on it unless the user explicitly asks about a third party, and then say what will be sent to which vendor.
2. Call `exposure_for` on each enabled premium connector and `ransom_watchlist_match`, respecting budgets.
3. Group findings by subject and kind, newest first, with vendor, confidence and first seen date. Leak site claims say "claimed by <group> on <date>, not confirmed".
4. For any finding about the user's own organisation involving personal information, add the NDB note and offer the breach notification skill.
5. Never print secrets; never suggest contacting the victim, regulator or vendor automatically.

Plugin tool `cyber_au_org_exposure` (registered by the `cyber-au` plugin) wraps steps 1 to 3. Input schema:
{schema_block(tool_schema)}

## Routine: `premium-exposure-watch`
- Added to `cron/jobs.json`, shipped paused; when an update adds it to an existing install it also arrives paused.
- Every 6 hours Australia/Sydney. Agent job that runs the skill with `since` = last run, with the routine budget share.
- Alerts only on new `finding_id`s at or above `alert.min_confidence`, to the owner's configured delivery target only. Quiet if nothing new.
- Writes a run record (vendors queried, calls, cost units, new findings count) to the audit log.

## Tests
- Watchlist validation: bad ABN checksum, duplicate domains, empty file.
- Skill eval cases in the offline harness: no findings; one infostealer finding; a leak site claim naming a similarly named organisation that is in `exclude`; a third party question (must ask before sending).
- Routine: two runs with the same fixture alert once.

## Acceptance criteria
- [ ] Skill passes its eval cases with all vendors mocked.
- [ ] Routine ships paused and alerts once per new finding.
- [ ] No finding about an organisation outside the watchlist is stored or alerted.

## Constraints
{COMMON_CONSTRAINTS}
""")
    return dict(key="premium-org-exposure", parent=E, milestone=M_V02,
                labels=["type:feature", "area:skills", "area:routines", AREA, "priority:p1"],
                title="Skill and routine: AU org exposure query and alert watch for the user's own domains, ABNs and brands",
                body=body)


def wiring_ticket():
    body = dedent(f"""
## Outcome
Premium and free exposure findings show up where analysts already look: the daily briefing, incident triage and breach notification.

## Changes
- **Daily briefing** ({{{{ref:routine-daily-briefing}}}}, epic {{{{ref:epic-routines}}}}): new section "Exposure of our organisation" after ASD items, listing new findings from the `exposures` table since the last briefing, grouped by kind, with confidence labels. Omitted entirely when no premium vendor is enabled and the free tracker has nothing. Respects `share_outside_profile`.
- **Incident triage** ({{{{ref:skill-incident-triage}}}}): when the incident touches a watchlist domain, call `cyber_au_org_exposure` for that subject and the last 30 days, and add "related exposure" evidence to the triage summary. Infostealer findings for affected users raise the suggested priority.
- **Breach notification** ({{{{ref:skill-ndb-breach-notification}}}}): accept an `exposure` finding id as input. Prefill what is known (data classes, counts, first seen), mark what is unknown, and start the 30 day assessment reminder. It drafts; it never notifies anyone.
- **Executive briefing** ({{{{ref:skill-executive-briefing}}}}): one line on exposure trends, counts only.
- **STIX export** ({{{{ref:store-stix-export}}}}): exports only findings with `stix_exportable: true`.

## Tests
- Briefing snapshot tests with zero, one and many findings, and with a non-shareable finding and a non-owner delivery target.
- Triage and NDB skill eval cases using synthetic findings.

## Acceptance criteria
- [ ] All four outputs include exposure data from fixtures, with confidence labels and no secrets.
- [ ] With every premium vendor off, all outputs are unchanged from before this ticket.

## Constraints
{COMMON_CONSTRAINTS}

Depends on {{{{ref:premium-interface}}}} and {{{{ref:premium-org-exposure}}}}.
""")
    return dict(key="premium-wiring", parent=E, milestone=M_V02,
                labels=["type:feature", "area:routines", "area:skills", AREA, "priority:p2"],
                title="Wire premium exposure findings into the daily briefing, incident triage and breach notification skills",
                body=body)


def vendor_ticket(c):
    c = dict(c)
    paid = c.get("paid", True)
    if paid:
        c["default_off"] = "Paid feed. Ships with `enabled: false`; bring your own licence."
    else:
        c["default_off"] = "Free, no licence needed. Still ships with `enabled: false` because it handles victim claims; the user turns it on."
    cache, store, stix = c["terms_flags"]
    c.setdefault("extra_criteria", [])
    c["extra_criteria"] = c["extra_criteria"] + [
        "Implements `PremiumConnector` from {{ref:premium-interface}} and passes its contract suite.",
        "All fixtures are synthetic or recorded against the vendor's documented test data; none contains a real victim, credential or personal information (CI check).",
        "Findings normalise to `ExposureFinding` with the terms flags in the Premium interface section applied.",
    ]
    t = connector_ticket(c)
    flags = dedent(f"""
## Premium interface
Paid or free: **{'paid, bring your own licence' if paid else 'free'}**. Implements {{{{ref:premium-interface}}}}; results feed {{{{ref:premium-org-exposure}}}}.

| Flag | Default |
|---|---|
| `cache` | `{cache}` |
| `store` | `{store}` |
| `stix_export` | `{str(stix).lower()}` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

Quota defaults go in `mcp/premium/vendors.yaml` from the rate limits above; the user sets `monthly_budget_units`.

""")
    t["body"] = t["body"].replace("\n## Files\n", "\n" + flags + "## Files\n", 1)
    t["parent"] = E
    t["labels"] = ["type:feature", "area:connectors", AREA, f"priority:{c['priority']}"]
    prefix = "Premium connector" if paid else "Connector (free)"
    t["title"] = f"{prefix}: {c['name']} (`{c['server']}`)"
    t["key"] = f"premium-{c['key']}"
    return t


def tickets():
    return [interface_ticket(), skill_ticket(), wiring_ticket()] + [vendor_ticket(c) for c in PREMIUM]
