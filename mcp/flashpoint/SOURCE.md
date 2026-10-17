# flashpoint

- Upstream: https://api.flashpoint.io/technical-intelligence/v2/indicators
- Auth: Bearer token from `FLASHPOINT_API_TOKEN` (paid Ignite licence). The value is read from the environment. It is not logged, stored, or sent on a redirect.
- Rate limit: Flashpoint has not published one. This connector allows a burst of 2, then one call every two seconds, and honours `Retry-After` on 429.
- Terms: Commercial licence. Session cache (memory only). Store metadata only. No STIX export. No sharing outside the profile. Redistribution forbidden.
- Verified: 17 October 2026
- Egress hosts: api.flashpoint.io

## Confirmed path

`GET https://api.flashpoint.io/technical-intelligence/v2/indicators`

On 17 October 2026 this URL returned HTTP 401 and `{"message":"Unauthorized"}` with no token. The same path returned 401 on 16 October 2026. No query parameter was visible, because the docs portal would not render the reference page. The connector therefore sends no query string and keeps only records whose `value` matches the requested value inside the returned document. A miss means the value was not in that document.

The response list key was also not on a page we could read. The connector accepts the first list of objects, preferring `items`, `indicators`, `data`, then `results`. Each object must include `value`. Any other shape is a warning, and `health --schema-drift` fails. Free text is wrapped as untrusted. The history log keeps metadata fields only (value, type, source reference, timestamps, score) and drops the summary.

## Not confirmed, and not implemented

`flashpoint_credential_exposure` is omitted.

On 17 October 2026 these portal URLs redirected to `login.flashpoint.io` (Ignite sign-in):

- https://docs.flashpoint.io/
- https://docs.flashpoint.io/reference
- https://docs.flashpoint.io/flashpoint/reference/list_indicators_technical_intelligence_v2_indicators_get

The credential sightings search path was not on a page we could read. Vendor-integration examples were not used. No credential endpoint is called.

`exposure_for` returns no findings for the same reason. An indicator collection is not treated as an exposure search, and indicator rows are not forced into an exposure kind.

## Default state

`mcp/servers.yaml` has `default_enabled: false`. A fresh install stays disabled when `FLASHPOINT_API_TOKEN` is set. The user turns it on with `enabled: true` in their profile `config.yaml`.

## Operator guide

Read-only indicator context from Flashpoint Ignite. This is a paid feed. It ships disabled until you set `enabled: true` for `mcp_servers.flashpoint` in your profile `config.yaml`. Put your own Ignite token in `FLASHPOINT_API_TOKEN`. An update does not change that switch.

| Tool | What it returns |
|---|---|
| `flashpoint_indicator` | Context for one indicator value: type, timestamps, score, and a short note |

`flashpoint_credential_exposure` is not included. On 17 October 2026 the docs portal at <https://docs.flashpoint.io/> redirected to an Ignite sign-in page, so the credential sightings search path could not be confirmed. It is not called.

### Terms

Commercial licence. Session cache. Store metadata only. No STIX export. No sharing outside the profile. Redistribution is forbidden.

| Flag | Default |
|---|---|
| `cache` | `session` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

`doctor` reports this server as `off (paid, bring your own licence)` until you enable it. The full note is [docs/premium/terms/flashpoint.md](../premium/terms/flashpoint.md).

A skill that calls this connector states these terms before the first call in a session.

Indicator notes are untrusted text. The connector does not keep them in the history log. Flashpoint has not published a rate limit. This connector allows a burst of two calls, then one every two seconds, and backs off on 429.

Attribution: Commercial licence. Session cache. Store metadata only. No STIX export.
