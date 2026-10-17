# Premium feeds

Paid feeds stay off until you bring your own licence and turn that server on. This page is the shared interface. It does not connect to a vendor, and it does not contain a licence key.

## Default state

Each premium server in `mcp/servers.yaml` has `default_enabled: false`. Paid servers are also marked `paid: true`. The free ransomware.live tracker is still disabled, because it carries victim claims. A fresh install renders `enabled: false` even when the licence variable is already set in `.env`. You turn a vendor on by setting `enabled: true` in your own `config.yaml`. `hermes profile update` keeps that choice.

`.env.template` lists the licence variables commented out, with the note "paid, bring your own licence".

`doctor` prints one of these for each paid vendor:

- `off (paid, bring your own licence)`
- `on`
- `on, key missing`

`doctor --premium` adds usage against the day, month and cost limits. The ledger month is Australia/Sydney.

## Terms flags

`mcp/premium/vendors.yaml` holds the conservative default from each vendor. The shared code enforces them:

| Flag | What it does |
| --- | --- |
| `cache` | `none` stores nothing. `session` keeps the response in memory and clears it when the session ends. `ttl` may touch disk, and only up to `cache_ttl_max_s`. A `ttl` cache needs a cap above zero. An entry older than the cap is deleted and is never served, including offline or when the vendor errors. |
| `store` | `none` does not write the intel store. `metadata` keeps counts, classes and references, and drops credential values. `full` still redacts passwords, cookies and tokens before anything is kept. |
| `stix_export` | When false, STIX export skips the finding and reports how many it skipped. |
| `share_outside_profile` | When false, a briefing sent anywhere other than the owner's channel omits the finding. |
| `redistribution` | `forbidden` unless you change it. `internal` and `allowed` are wider, so they count as a relaxation. |

You can relax a flag under `cyber_au.premium.<vendor>.terms` only if you also set `contract_ref` (free text, for example a contract number). The change is written to the audit log. Tightening a flag does not need a contract reference.

```yaml
cyber_au:
  premium:
    upguard:
      terms:
        stix_export: true
        contract_ref: "CN-100"
      quota:
        calls_per_day: 20
        monthly_budget_units: 100
```

## Budgets

The ledger is `plugin-data/cyber-au/premium-ledger.sqlite`, or `$CYBERAU_DATA_DIR/premium-ledger.sqlite` when that variable is set. It records calls and cost units per vendor, per day, in Australia/Sydney.

The `pre_tool_call` guard blocks a call that would pass `calls_per_day`, `calls_per_month` or `monthly_budget_units`. The message names the limit, and the block is logged. A call whose cost is above `approval_above_units` asks for approval first. `hard_stop` defaults to true. Bulk tools stop at `max_pages` (default 5). Cron routines get their own share of the limit (default 50 percent), so a routine cannot spend the whole allowance.

Where a vendor has not published a number, the quota is not set. Set `monthly_budget_units` yourself. Recorded Future's daily cap is per subscription, so copy that number into your config. ransomware.live defaults to 24 calls a day and 500,000 a month: the monthly figure is the published cap, and 24 is one poll an hour.

## Privacy

Exposure data often contains personal information about staff or customers. Treat it under the Australian Privacy Principles: collect only what the task needs (APP 3), use it only for the security purpose it was collected for (APP 6), and take reasonable steps to protect it and destroy it when no longer needed (APP 11). Most vendors are overseas, so query parameters sent to them are a cross-border disclosure to consider under APP 8. This is guidance for the operator, not legal advice.

The store keeps a finding for 90 days (`expires_at`), then the retention job deletes it. A repeat finding updates `observed_at` and the counts. Passwords, session cookies, tokens, `email:password` lines, URL credentials, Australian phone numbers, tax file, Medicare, passport and licence numbers, and dates of birth are replaced with a type and a short hash before anything leaves the connector. They are not stored and not displayed. Names, street addresses and free-form passwords that contain spaces cannot be found by pattern, so the shared code never stores vendor record bodies, only the fields in the finding schema. Free text that is returned (subject, reference and data classes) is wrapped as untrusted. The short hash is a label, not protection: a weak password can be guessed back from it, so do not paste redacted output into places that are less protected than the original.

Leak site claims are allegations made by criminals. They are labelled `unverified_claim`. Do not download leaked files or follow leak site links. Findings about organisations that are not on your watchlist (the store requires a watchlist on every write) are not stored and are not mentioned in briefings unless you ask. Nothing in this distribution contacts the OAIC, ASD, affected individuals, the victim organisation or a vendor. A skill can draft. A person sends. A finding about your own organisation may start the clock for assessing a suspected eligible data breach under the NDB scheme. Hand that to the breach notification skill.

## Vendor notes

Generated from `mcp/premium/vendors.yaml`:

- [Hudson Rock Cavalier](terms/hudsonrock.md)
- [SpyCloud Enterprise Protection](terms/spycloud.md)
- [UpGuard CyberRisk](terms/upguard.md)
- [ransomware.live](terms/ransomlive.md)
- [Recorded Future](terms/recordedfuture.md)
- [Flashpoint Ignite](terms/flashpoint.md)
- [Intel 471 Titan](terms/intel471.md)
- [Google Threat Intelligence DTM](terms/gtidtm.md)
- [CrowdStrike Falcon Recon](terms/csrecon.md)
- [SOCRadar](terms/socradar.md)
- [DarkOwl Vision](terms/darkowl.md)
- [Flare](terms/flare.md)
