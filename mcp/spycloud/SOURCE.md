# spycloud

- Upstream: https://api.spycloud.io/enterprise-v2/breach/data/watchlist and https://api.spycloud.io/enterprise-v2/breach/catalog/{id} (docs: https://docs.spycloud.com/public-sc/docs/api-guidelines). Watchlist membership for doctor: https://api.spycloud.io/enterprise-v2/watchlist/identifiers. No salt is sent, so hashed values stay on the key's own setting.
- Auth: `SPYCLOUD_API_KEY` sent as the `X-API-KEY` header. Never logged. Bring your own licence. No key is bundled.
- Rate limit: HTTP 429 is documented and no quota number is published. The client stays at 1 request per second and honours `Retry-After`.
- Terms: Commercial licence. Off by default. Session cache for records. Breach catalogue metadata for 24 hours. Store metadata only. No STIX export. Prefer hashed values when the licence allows. State these terms before the first call in a session.
- Verified: 2026-10-17
- Egress hosts: api.spycloud.io
