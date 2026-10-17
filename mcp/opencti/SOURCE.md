# opencti

- Upstream: https://docs.opencti.io/
- Auth: `OPENCTI_URL` and `OPENCTI_TOKEN` for a read-only user. The token is sent as a bearer header and is never logged.
- Rate limit: 2 requests per second, burst 10, per instance host. This is a client ceiling. Stay under the limit set on the instance.
- Terms: OpenCTI Community Edition is Apache-2.0. Enterprise Edition has its own licence. Data in your instance stays under the terms you agreed with its sources. This connector is not endorsed by Filigran.
- Verified: 2026-10-16
- Egress hosts: user supplied. The connector allows only the host of `OPENCTI_URL`, plus any host listed here. Redirects to any other host are refused.

The static allowlist ships with no hosts because the instance is yours. Private, link-local and carrier-grade NAT addresses stay blocked.

## Operator guide

Read-only search of actors, malware, indicators and reports on an OpenCTI instance you run.

| Tool | What it returns |
|---|---|
| `opencti_search_entities` | Actors, malware, indicators and reports matching a query |
| `opencti_get_indicator_context` | Relationships and sightings for an indicator |

### Off by default: licence terms

Doctor lists this connector as off by default: licence terms.

OpenCTI Community Edition is Apache-2.0. Enterprise Edition has its own licence. Data in your instance stays under the terms you agreed with its sources. This connector is not endorsed by Filigran.

A fresh install renders `enabled: false` for `mcp_servers.opencti` even when `OPENCTI_URL` and `OPENCTI_TOKEN` are set. Turn it on by setting `enabled: true` in your profile `config.yaml`. `hermes profile update` keeps that choice.

`OPENCTI_URL` is the instance origin. `OPENCTI_TOKEN` is an API token for a read-only user. The connector calls `https://<host>/graphql` on that host only and refuses a redirect to any other host. The host must not resolve to a private, link-local or carrier-grade NAT address.

Names, descriptions, patterns and other free text are untrusted data.

Upstream: https://docs.opencti.io/
