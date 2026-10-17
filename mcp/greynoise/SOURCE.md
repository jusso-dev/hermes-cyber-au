# greynoise

- Upstream: https://docs.greynoise.io/reference/getcommunityip
- Auth: optional `GREYNOISE_API_KEY` sent as the `key` header. Never logged.
- Rate limit: 10 unauthenticated IP lookups a day in the GreyNoise usage guide (2 October 2026). The API reference example still shows 100 a day (7 May 2026). A free account raises the quota. This connector allows 1 request a second.
- Terms: GreyNoise terms of service. Cite GreyNoise.
- Verified: 2026-10-16
- Egress hosts: api.greynoise.io

## Operator guide

Read-only noise and RIOT classification from the GreyNoise Community API.

| Tool | What it returns |
|---|---|
| `greynoise_ip` | Whether one IP is internet background noise, a known benign service, or not observed |

An optional `GREYNOISE_API_KEY` raises the daily lookup quota. The usage guide shows 10 unauthenticated lookups a day. This connector stays at one request a second. Names and messages are untrusted text.

GreyNoise Community. Cite GreyNoise.
