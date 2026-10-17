# SOCRadar (company incidents)

Read-only company incidents from SOCRadar incidents API v4. The server ships disabled. Paid, bring your own licence.

Generated from `mcp/socradar/SOURCE.md` and `mcp/premium/vendors.yaml`. Not legal advice.

| Tool | What it returns |
| --- | --- |
| `socradar_incidents` | Company incidents in a date range, mapped to exposure kinds |

Set `SOCRADAR_API_KEY` and `SOCRADAR_COMPANY_ID` in the profile `.env`. The company id is numeric. Turn the server on with `enabled: true` under `mcp_servers.socradar` in your profile `config.yaml`. A fresh install stays off even when the key is present, and a profile update keeps the value you set.

A skill that calls this connector states the terms below before the first call in a session.

## Terms

Commercial licence. Session cache. Store metadata only. No STIX export.

| Flag | Default |
| --- | --- |
| `cache` | `session` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

Doctor lists the server as off until you enable it. Quota calls per day and per month are not set, because SOCRadar does not publish a rate limit. You set `monthly_budget_units`. HTTP 429 honours `Retry-After`.

Free text from the feed is wrapped as untrusted text. Credential values are not stored.

A result with `cache: snapshot` comes from a local file, not SOCRadar. It carries a warning, is never stored, and is refused by `exposure_for`. Test fixtures are synthetic. `health --live` reports not ok when the key is missing, the fetch fails, or the answer is cached.

## Dates and severity

`since` and `until` are `YYYY-MM-DD` calendar dates in Australia/Sydney. They are sent as `start_date` and `end_date`. `severity` must be one of `INFO`, `LOW`, `MEDIUM`, `HIGH` or `CRITICAL` and is sent as `severities`.

Alarm types are mapped only where a vendor-published integration gives the example string. Detail, including parameters that were not confirmed and are not sent, is in `mcp/socradar/SOURCE.md`.

## Attribution

Commercial licence. Session cache. Store metadata only. No STIX export.
