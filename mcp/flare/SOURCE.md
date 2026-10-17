# flare

- Upstream: https://api.docs.flare.io/introduction/getting-started
- Auth: `FLARE_API_KEY` (raw `Authorization` header) is exchanged at `POST /tokens/generate` for a bearer token that lasts 1 hour. Optional `FLARE_TENANT_ID` selects the tenant. Neither value is logged.
- Rate limit: Search tier, 1 request a second (under the Basic tier of 4 a second). On HTTP 429 `RATELIMIT_REACHED`, wait for `Retry-After` or 10 seconds, then retry once. Global Search remaining is read from `X-Flare-Global-Searches-Remaining`.
- Terms: Commercial licence. Session cache for events and credentials. Store event metadata only. No STIX export of Flare content. No sharing outside the profile. Off by default until you set `enabled: true`. Read only: this connector does not create or change identifiers, groups, matching policies or severity rules.
- Verified: 2026-10-16
- Egress hosts: api.flare.io
