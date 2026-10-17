# hudson-rock

- Upstream: https://docs.hudsonrock.com/docs/domain-search
- Auth: `api-key` header. The value is `HUDSONROCK_API_KEY` from the profile environment. Never logged. Bring your own paid Cavalier licence. Do not use the free preview key for the older Cavalier v2 base.
- Rate limit: 40 requests per 10 seconds, under the documented ceiling of 50 requests per 10 seconds. Client timeout 90 seconds.
- Terms: Commercial licence. Session cache only. Store counts and metadata only. No STIX export. No sharing outside the profile.
- Verified: 2026-10-17
- Egress hosts: api.hudsonrock.com

State these terms before the first call in a session. The connector returns counts and overview statistics. It does not return passwords, cookies or other credential values.
