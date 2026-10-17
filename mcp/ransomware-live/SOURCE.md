# ransomware-live

- Upstream: https://www.ransomware.live/apidocs
- Auth: optional `RANSOMWARE_LIVE_API_KEY` sent as the `X-API-KEY` header. Never logged. Without it the connector uses the public v2 API.
- Rate limit: PRO API 500,000 requests a month, then 429. v2 is rate limited, with no published number. Self-imposed: one poll an hour (one hour cache; limiter allows a short retry burst then averages one request an hour).
- Terms: Free community project. Victim entries are claims scraped from criminal leak sites, not confirmed incidents. Check the site's terms before redistributing. Default flags: store metadata, no STIX export of victim names. Ships off by default: licence terms.
- Verified: 2026-10-16
- Egress hosts: api-pro.ransomware.live, api.ransomware.live
