# Hudson Rock Cavalier

Read-only infostealer exposure counts for domains on your org-exposure watchlist. The server ships disabled. Bring your own paid Cavalier licence in `HUDSONROCK_API_KEY`. Do not use the free preview key for the older Cavalier v2 base.

| Tool | What it returns |
|---|---|
| `hudsonrock_domain_exposure` | Counts of compromised employees, users and third parties, with first and last compromise dates. Passwords and cookies are never returned. |
| `hudsonrock_domain_overview` | Vendor overview statistics for one watchlist domain. Overview timestamps are the earliest and latest of the vendor's last-compromise and last-upload times. |

It ships off by default because of the licence terms. Doctor shows `hudsonrock: off (paid, bring your own licence)` until you set `enabled: true` in your profile `config.yaml`. A later update keeps that choice. State these terms before the first call in a session:

Commercial licence. Session cache only. Store counts and metadata only. No STIX export. No sharing outside the profile.

Requests stay under the documented ceiling of 50 per 10 seconds. The client waits at most 90 seconds. Counts and metadata can be kept for the profile. Credential values are not stored and are not returned.

Upstream documentation: https://docs.hudsonrock.com/
