# ransomware-live

- Upstream: https://www.ransomware.live/apidocs
- Auth: optional `RANSOMWARE_LIVE_API_KEY` sent as the `X-API-KEY` header. Never logged. Without it the connector uses the public v2 API.
- Rate limit: PRO API 500,000 requests a month, then 429. v2 is rate limited, with no published number. Self-imposed: one poll an hour (one hour cache; limiter allows a short retry burst then averages one request an hour).
- Terms: Free community project. Victim entries are claims scraped from criminal leak sites, not confirmed incidents. Check the site's terms before redistributing. Default flags: store metadata, no STIX export of victim names. Ships off by default: licence terms.
- Verified: 2026-10-16
- Egress hosts: api-pro.ransomware.live, api.ransomware.live

## Operator guide

Read-only leak-site claims that name Australian organisations. Each record is an unverified claim, not a confirmed incident.

This connector is off by default: licence terms. It handles victim claims, so a fresh install stays disabled even when `RANSOMWARE_LIVE_API_KEY` is set. Turn it on by setting `enabled: true` under `mcp_servers.ransomlive` in your profile `config.yaml`. `hermes profile update` keeps that choice and will not switch it back on or off.

A skill that calls this connector states the terms before the first call in a session.

### Terms

Free community project. Victim entries are claims scraped from criminal leak sites, not confirmed incidents. Check the site's terms before redistributing. Default flags: store metadata, no STIX export of victim names, do not share records outside the profile, and redistribution is forbidden.

Upstream terms: https://www.ransomware.live/apidocs

### Tools

| Tool | What it returns |
|---|---|
| `ransom_au_victims` | Australian leak-site claims, newest first, filtered by date, sector or group |
| `ransom_watchlist_match` | Recent claims that match the org-exposure watchlist (names, brands, domains) |

Dates use Australia/Sydney. The watchlist is the user-owned file `watchlists/org-exposure.yaml` in the profile (or `CYBERAU_ORG_WATCHLIST`). Watched values are matched locally and are not sent to the upstream API.

### Access

`RANSOMWARE_LIVE_API_KEY` is optional. With a free key the connector calls `https://api-pro.ransomware.live/victims/?country=AU` and sends the key in `X-API-KEY`. Without a key it calls `https://api.ransomware.live/v2/recentvictims` and keeps rows whose country is AU. The v2 country path is not used: it returned 404 on 16 October 2026.

The PRO API allows 500,000 requests a month and returns 429 after that. This connector polls at most about once an hour. Results are cached for one hour.

If the live fetch fails and a cached copy exists, the result is marked `stale` with a warning. With no cached copy it returns no records and a warning that ransomware.live is unavailable. Offline mode (`CYBERAU_OFFLINE=1`) reads the cache only and ends the same way. The package ships no victim data: the synthetic claims under `tests/fixtures/` are for tests and are never served at runtime.

`CYBERAU_RANSOMLIVE_SNAPSHOT` points at an operator-supplied JSON file in the v2 or PRO shape. When it is set it is used instead of the live API, marked `snapshot`, with a warning that it is the operator-supplied snapshot and not a live fetch. Tests use it to pin the fixtures. A snapshot is never written to the metadata store. `--schema-drift` checks that file, and reports "no local copy to check" when it is not set. `health --live` fails unless the live service answered.

Attribution on every result: ransomware.live. Victim entries are leak-site claims, not confirmed incidents.
