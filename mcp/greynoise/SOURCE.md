# greynoise

- Upstream: https://docs.greynoise.io/reference/getcommunityip
- Auth: optional `GREYNOISE_API_KEY` sent as the `key` header. Never logged.
- Rate limit: 10 unauthenticated IP lookups a day in the GreyNoise usage guide (2 October 2026). The API reference example still shows 100 a day (7 May 2026). A free account raises the quota. This connector allows 1 request a second.
- Terms: GreyNoise terms of service. Cite GreyNoise.
- Verified: 2026-10-16
- Egress hosts: api.greynoise.io
