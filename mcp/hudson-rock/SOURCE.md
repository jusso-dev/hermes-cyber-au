# hudson-rock

- Upstream: https://docs.hudsonrock.com/docs/domain-search
- Auth: `api-key` header. The value is `HUDSONROCK_API_KEY` from the profile environment. Never logged. Bring your own paid Cavalier licence. Do not use the free preview key for the older Cavalier v2 base.
- Rate limit: 40 requests per 10 seconds, under the documented ceiling of 50 requests per 10 seconds. Client timeout 90 seconds.
- Terms: Commercial licence. Session cache only. Store counts and metadata only. No STIX export. No sharing outside the profile.
- Verified: 2026-10-17
- Egress hosts: api.hudsonrock.com

State these terms before the first call in a session. The connector returns counts and overview statistics. It does not return passwords, cookies or other credential values.

## Fallback and fixtures

The fallback ladder is a live fetch, then the connector's own session cache (a stale copy after a failed fetch, or any cached copy in offline mode), then unavailable. No snapshot ships with the connector. When there is no live or cached answer, or the key is missing or rejected, every tool returns empty data with a warning that the Hudson Rock source is unavailable. An operator may point `CYBERAU_HUDSONROCK_SEARCH_SNAPSHOT` or `CYBERAU_HUDSONROCK_OVERVIEW_SNAPSHOT` at a saved response. Answers from it carry a warning that they came from the operator-supplied snapshot file, not a live fetch, and are never stored as findings. The synthetic test fixtures live under `tests/fixtures/`. Only the offline schema check (`check_schema` without `live`) reads them, and it never returns them as data. A live health check always makes a fresh call.

## Operator guide

Read-only infostealer exposure counts for domains on your org-exposure watchlist. The server ships disabled. Bring your own paid Cavalier licence in `HUDSONROCK_API_KEY`. Do not use the free preview key for the older Cavalier v2 base.

| Tool | What it returns |
|---|---|
| `hudsonrock_domain_exposure` | Counts of compromised employees, users and third parties, with first and last compromise dates. Passwords and cookies are never returned. |
| `hudsonrock_domain_overview` | Vendor overview statistics for one watchlist domain. Overview timestamps are the earliest and latest of the vendor's last-compromise and last-upload times. |

It ships off by default because of the licence terms. Doctor shows `hudsonrock: off (paid, bring your own licence)` until you set `enabled: true` in your profile `config.yaml`. A later update keeps that choice. State these terms before the first call in a session:

Commercial licence. Session cache only. Store counts and metadata only. No STIX export. No sharing outside the profile.

Requests stay under the documented ceiling of 50 per 10 seconds. The client waits at most 90 seconds. Counts and metadata can be kept for the profile. Credential values are not stored and are not returned.

Upstream documentation: https://docs.hudsonrock.com/
