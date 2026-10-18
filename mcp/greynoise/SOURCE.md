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

### Fallback and fixtures

If the live fetch fails, or `CYBERAU_OFFLINE=1` is set, the connector's own cache answers when it has a copy of that address. When there is no cached copy, the tool returns no record and a warning that GreyNoise is unavailable. No GreyNoise record is shipped with the connector, so nothing from the repo is ever served as GreyNoise data.

`CYBERAU_GREYNOISE_SNAPSHOT` may point at an operator-supplied Community API response file. It is read instead of the live API, and every answer carries a warning that it came from that file, not a live fetch. The sample responses used by the tests live in `tests/fixtures/`.
