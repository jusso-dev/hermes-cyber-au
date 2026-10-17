# crowdstrike-recon

- Upstream: https://developer.crowdstrike.com/api-reference/collections/recon/
- Auth: OAuth2 client credentials. `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` from the profile `.env`. Optional `FALCON_BASE_URL`. Values are never logged.
- Rate limit: Falcon returns the ceiling in response headers. Back off on 429 using `Retry-After`. The local limiter stays under that ceiling.
- Terms: Commercial licence. Session cache. Store metadata only. No STIX export. Read scope only. Off by default: licence terms.
- Verified: 2026-10-16
- Egress hosts: api.crowdstrike.com

Recon calls go through the official FalconPy SDK (`query_notifications`, `get_notifications`, `query_rules`, `get_rules`). Creating rules is out of scope.
