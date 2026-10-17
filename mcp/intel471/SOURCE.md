# intel471

- Upstream: https://github.com/intel471/titan-client-python (API host `https://api.intel471.com/v1`)
- Auth: HTTP Basic. `INTEL471_EMAIL` is the username and `INTEL471_API_KEY` is the password. Values come from the profile `.env`. Never logged.
- Rate limit: not published. This connector stays at 4 requests a second with a burst of 8 and backs off on HTTP 429 using `Retry-After`.
- Terms: Commercial licence. Session cache. The vendor client's own long cache stays off. Store metadata only. No STIX export. Off by default: licence terms. Breach alerts that name victims stay inside the profile.
- Verified: 2026-10-17
- Egress hosts: api.intel471.com

Reads alerts, breach alerts and credential occurrence counts only. It does not create or edit watchers, and it never sends `markAsRead=true`.

Live health makes real calls, bypassing the cache, and fails on a cached or snapshot answer or a missing key.
