# OpenCTI (your own instance)

Read-only search of actors, malware, indicators and reports on an OpenCTI instance you run.

| Tool | What it returns |
|---|---|
| `opencti_search_entities` | Actors, malware, indicators and reports matching a query |
| `opencti_get_indicator_context` | Relationships and sightings for an indicator |

## Off by default: licence terms

Doctor lists this connector as off by default: licence terms.

OpenCTI Community Edition is Apache-2.0. Enterprise Edition has its own licence. Data in your instance stays under the terms you agreed with its sources. This connector is not endorsed by Filigran.

A fresh install renders `enabled: false` for `mcp_servers.opencti` even when `OPENCTI_URL` and `OPENCTI_TOKEN` are set. Turn it on by setting `enabled: true` in your profile `config.yaml`. `hermes profile update` keeps that choice.

`OPENCTI_URL` is the instance origin. `OPENCTI_TOKEN` is an API token for a read-only user. The connector calls `https://<host>/graphql` on that host only and refuses a redirect to any other host. The host must not resolve to a private, link-local or carrier-grade NAT address.

Names, descriptions, patterns and other free text are untrusted data.

Upstream: https://docs.opencti.io/
