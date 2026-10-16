---
key: "premium-org-exposure"
title: "Skill and routine: AU org exposure query and alert watch for the user's own domains, ABNs and brands"
labels: ["type:feature", "area:skills", "area:routines", "area:premium-feeds", "priority:p1"]
milestone: "v0.2"
parent: "epic-premium"
---
## Outcome
An `au-org-exposure` skill that answers "is my organisation exposed?" from every enabled premium feed and the free ransomware tracker, plus a paused routine that alerts the owner when a new finding matches their own domains, ABNs or brands.

## Watchlist
User-owned file, created by `cyberau watchlist init --org`, validated on load, never shipped:
```yaml
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
```
- ABNs are validated with the ATO checksum (subtract 1 from the first digit, weights 10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, sum divisible by 89). Replace the example before use. Vendors search by name and domain, so an ABN expands to the entity's registered and business names through ABN Lookup web services (free GUID registration; confirm the endpoint at build time) and only those names are sent.
- Shares the brand and domain lists with {{ref:routine-watchlists}} so the user keeps one list.

## Skill: `skills/au-org-exposure/SKILL.md`
Frontmatter `metadata.hermes.related_skills: [incident-triage, ndb-breach-notification, executive-briefing]`.
Procedure:
1. Load the watchlist; refuse to search for names that are not on it unless the user explicitly asks about a third party, and then say what will be sent to which vendor.
2. Call `exposure_for` on each enabled premium connector and `ransom_watchlist_match`, respecting budgets.
3. Group findings by subject and kind, newest first, with vendor, confidence and first seen date. Leak site claims say "claimed by <group> on <date>, not confirmed".
4. For any finding about the user's own organisation involving personal information, add the NDB note and offer the breach notification skill.
5. Never print secrets; never suggest contacting the victim, regulator or vendor automatically.

Plugin tool `cyber_au_org_exposure` (registered by the `cyber-au` plugin) wraps steps 1 to 3. Input schema:
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "subject": {
      "type": "string",
      "description": "domain, ABN, brand or watchlist entry id; default all watchlist entries"
    },
    "since": {
      "type": "string",
      "format": "date"
    },
    "kinds": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "vendors": {
      "type": "array",
      "items": {
        "type": "string"
      }
    }
  },
  "required": []
}
```

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
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`).

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
