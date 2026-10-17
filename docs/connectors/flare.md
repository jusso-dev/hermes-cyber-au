# Flare threat exposure management

Read-only events and credential counts from the Flare API. The connector ships off until you set `enabled: true` in your profile `config.yaml`. `doctor` lists it as off by default: licence terms (`off (paid, bring your own licence)`).

Bring your own licence. Put `FLARE_API_KEY` in the profile `.env`. A restricted key with Read Tenant permission and an expiry date is the right choice. `FLARE_TENANT_ID` is optional when the key can reach more than one tenant.

Before the first Flare call in a session, state these terms: Commercial licence. Session cache for events and credentials. Store event metadata only. No STIX export of Flare content. No sharing outside the profile.

The connector does not create or change identifiers, groups, matching policies or severity rules. `doctor --premium` lists watchlist entries Flare is not monitoring so you can add them in Flare.

| Tool | What it returns |
|---|---|
| `flare_tenant_exposure` | Events for the tenant's identifiers since a date, mapped to exposure kinds. No credential values. |
| `flare_identifier_events` | Events for one monitored identifier. |
| `flare_identifiers` | Identifiers monitored in the tenant, compared with the local watchlist. |
| `flare_domain_credentials` | Counts of leaked credentials for one watchlist email domain, by source type and imported date. This spends Global Search quota and asks first above the daily count you set. |
| `flare_quota_status` | Global Search searches remaining this month, from the last response header. |

Tenant searches are preferred. `flare_domain_credentials` accepts only a domain in your watchlist `email_domains`, and the daily count and floor are checked before every page of a Global Search. A list Flare returns in more pages than were read comes back with a partial warning. Password and email queries are not tools. A ransomware leak site claim is marked as reported by the vendor, and the briefing says the claim is unconfirmed.

Search calls stay at one request a second. A 429 waits for `Retry-After`, or 10 seconds when that header is absent, then retries once. The API token is refreshed before the one hour expiry and is not logged.

The optional `flare_mcp` entry points at `https://api.flare.io/mcp` (beta), ships disabled, and includes only the published read tools.

Upstream: https://api.docs.flare.io/introduction/getting-started. Verified 16 October 2026.
