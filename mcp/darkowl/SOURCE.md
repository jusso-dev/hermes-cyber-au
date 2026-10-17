# darkowl

- Upstream: https://api.darkowl.com/api/v1/search
- Auth: HMAC-SHA1 of the method, the decoded path and query, and a UTC `Date` header. Sent as `Authorization: OWL <public key>:<base64 signature>`. The private key is only used to sign and is never logged.
- Rate limit: per licence. Local ceiling is 1 request a second, burst 2. Back off on 429 and honour `Retry-After`.
- Terms: Commercial licence. Session cache. Store counts and links only, no snippets. No STIX export. Off by default: licence terms.
- Verified: 2026-10-17
- Egress hosts: api.darkowl.com

## Operator guide

Read-only dark web search for watchlist names, brands and domains. Paid, bring your own licence. The server ships disabled (`enabled: false`) even when `DARKOWL_PUBLIC_KEY` and `DARKOWL_PRIVATE_KEY` are set. Turn it on with `enabled: true` under `mcp_servers.darkowl` in your profile `config.yaml`. `hermes profile update` keeps that file, so an update does not switch the connector back off or on.

`doctor` reports `darkowl: off (paid, bring your own licence)` until you enable it.

### Off by default: licence terms

State these terms before the first DarkOwl call in a session.

Commercial licence. Session cache. Store counts and links only, no snippets. No STIX export.

| Flag | Default |
|---|---|
| `cache` | `session` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

Nothing in this connector is shared outside the profile, and nothing is exported as STIX.

### Tool

| Tool | What it returns |
|---|---|
| `darkowl_search_watchlist` | Hit counts, first and last seen dates, and source types for up to 20 terms |

`since` is a `YYYY-MM-DD` date in Australia/Sydney. It filters on the crawl date.

Search text is hostile. Snippets and titles are wrapped as untrusted text and capped. They are not written to the intel store. Links in that text are removed. URLs found in a result are never requested.

When `CYBERAU_DARKOWL_SNAPSHOT` points at a local file, the answer comes from that file, carries `cache: snapshot` and a warning, and is neither stored nor turned into exposure findings. A live health check fails when either key is missing.

### Licence

Names only. Put the values in the profile `.env`. Do not commit them.

- `DARKOWL_PUBLIC_KEY` (required)
- `DARKOWL_PRIVATE_KEY` (required, used only to sign, never logged)

### Auth and limits

Each request is signed with HMAC-SHA1 over the HTTP method, the decoded path and query, and a UTC `Date` header. The header is `Authorization: OWL <public key>:<base64 signature>`.

The published licence limit is per contract. This connector stays at 1 request a second, with a burst of 2, and honours `Retry-After` on HTTP 429.

Upstream: `GET https://api.darkowl.com/api/v1/search`. A live health check uses `GET https://api.darkowl.com/api/v1/test`.
