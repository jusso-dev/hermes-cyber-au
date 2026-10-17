# intel471

- Upstream: https://github.com/intel471/titan-client-python (API host `https://api.intel471.com/v1`)
- Auth: HTTP Basic. `INTEL471_EMAIL` is the username and `INTEL471_API_KEY` is the password. Values come from the profile `.env`. Never logged.
- Rate limit: not published. This connector stays at 4 requests a second with a burst of 8 and backs off on HTTP 429 using `Retry-After`.
- Terms: Commercial licence. Session cache. The vendor client's own long cache stays off. Store metadata only. No STIX export. Off by default: licence terms. Breach alerts that name victims stay inside the profile.
- Verified: 2026-10-17
- Egress hosts: api.intel471.com

Reads alerts, breach alerts and credential occurrence counts only. It does not create or edit watchers, and it never sends `markAsRead=true`.

Live health makes real calls, bypassing the cache, and fails on a cached or snapshot answer or a missing key.

## Operator guide

Read-only watcher alerts, breach alerts and credential occurrence counts from Intel 471 Titan.

| Tool | What it returns |
|---|---|
| `intel471_watcher_alerts` | Recent watcher alerts with watcher name, source type and timestamp |
| `intel471_breach_alerts` | Breach alerts that mention a name or domain on your org-exposure watchlist |
| `intel471_credential_exposure` | Credential occurrence counts for one watchlist domain |

This connector is off by default: licence terms. A fresh install renders `enabled: false` even when `INTEL471_EMAIL` and `INTEL471_API_KEY` are already in the profile `.env`. Turn it on by setting `enabled: true` under `mcp_servers.intel471` in your own `config.yaml`. `hermes profile update` keeps that choice. `doctor` lists the server as off until you do.

Bring your own licence. Put the registered email and the Titan API key in the profile `.env` as `INTEL471_EMAIL` and `INTEL471_API_KEY`. Nothing in this repository is a licence key.

### Terms

Commercial licence. Session cache. The vendor client's own long cache stays off. Store metadata only. No STIX export. Redistribution is forbidden. Breach alerts that name victims stay inside the profile: the name is not written into the metadata store, it is not exported as STIX, and it is not included in a briefing that leaves the owner's channel.

Before the first Intel 471 call in a session, state those terms.

The flags and the quota note are also in [the premium terms page](../premium/terms/intel471.md). Titan does not publish a request quota. This connector stays at 4 requests a second, burst 8, and backs off when the service sends HTTP 429 with `Retry-After`. Set `monthly_budget_units` yourself.

### What it will not do

Watchers are configured in Titan. This connector only reads alerts, breach alerts and credential counts. It does not create, edit or delete watchers, and it does not mark alerts as read. Credential passwords and logins are not requested, not returned and not cached: credential responses skip the session cache, so they are unavailable offline. A result served from a local snapshot or an expired cached copy carries a warning, and a snapshot is never written to the metadata store. A query that is not on your org-exposure watchlist is not sent.

Upstream: <https://github.com/intel471/titan-client-python>. API host: `api.intel471.com`.
