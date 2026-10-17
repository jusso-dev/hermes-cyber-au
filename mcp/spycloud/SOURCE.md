# spycloud

- Upstream: https://api.spycloud.io/enterprise-v2/breach/data/watchlist and https://api.spycloud.io/enterprise-v2/breach/catalog/{id} (docs: https://docs.spycloud.com/public-sc/docs/api-guidelines). Watchlist membership for doctor: https://api.spycloud.io/enterprise-v2/watchlist/identifiers. No salt is sent, so hashed values stay on the key's own setting.
- Auth: `SPYCLOUD_API_KEY` sent as the `X-API-KEY` header. Never logged. Bring your own licence. No key is bundled.
- Rate limit: HTTP 429 is documented and no quota number is published. The client stays at 1 request per second and honours `Retry-After`.
- Terms: Commercial licence. Off by default. Session cache for records. Breach catalogue metadata for 24 hours. Store metadata only. No STIX export. Prefer hashed values when the licence allows. State these terms before the first call in a session.
- Verified: 2026-10-17
- Egress hosts: api.spycloud.io

## Operator guide

Read-only breach and malware exposure for the domains on your SpyCloud watchlist. The connector ships disabled. You bring your own licence in `SPYCLOUD_API_KEY` and set `enabled: true` in your profile `config.yaml`. `hermes profile update` keeps that choice. No licence key is bundled.

This connector is off by default: licence terms. This page quotes them. `doctor` prints `off (paid, bring your own licence)` while the server is disabled. The SpyCloud watchlist check names these terms and links here.

| Tool | What it returns |
|---|---|
| `spycloud_watchlist_exposure` | Exposure records since a date, summarised by type and severity. Credential values are redacted. |
| `spycloud_breach_info` | Title, publish date, record count and data classes for one breach |

Auth is the `X-API-KEY` header. Put the key in the profile `.env` as `SPYCLOUD_API_KEY`. The server receives `${SPYCLOUD_API_KEY}`.

Records use a session cache and are not written to disk. Breach catalogue metadata is kept for 24 hours. The intel store keeps metadata only. STIX export is off. Sharing outside the profile is off. Redistribution is forbidden.

SpyCloud can return hashed values when hashing is enabled on your key. This connector prefers that and does not send a salt.

The public docs document HTTP 429 and do not publish a quota. This client stays at one request per second and honours `Retry-After`. Set `monthly_budget_units` yourself.

Before the first SpyCloud call in a session, state the terms below. The feed is paid and stays off until you enable a licence you already hold.

### Terms

Quoted from `mcp/premium/vendors.yaml`. Not legal advice.

| Flag | Default |
|---|---|
| `cache` | `session` |
| `cache_ttl_max_s` | `0` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

Commercial licence. Session cache for records. Store metadata only. No STIX export. Prefer hashed values when the licence allows.

`doctor` compares the SpyCloud watchlist with your local org-exposure watchlist and reports domains missing from either. That file lives in your profile at `watchlists/org-exposure.yaml`. It is not shipped in this repository.

Vendor documentation: https://docs.spycloud.com/public-sc/docs/api-guidelines

See also [the premium terms note](../premium/terms/spycloud.md).
