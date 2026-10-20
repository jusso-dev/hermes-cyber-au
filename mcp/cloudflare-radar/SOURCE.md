# cloudflare-radar

- Upstream: Cloudflare Radar API, https://developers.cloudflare.com/radar/ (REST, `https://api.cloudflare.com/client/v4/radar`)
- Auth: `CLOUDFLARE_RADAR_API_TOKEN`, a custom API token with only Account > Radar > Read, sent as `Authorization: Bearer`. Never logged.
- Rate limit: Cloudflare client API allows 1,200 requests per 5 minutes per token. Going over blocks calls for 5 minutes. This connector allows 2 requests a second and reports `retry-after` on 429.
- Terms: Cloudflare Radar API data is CC BY-NC 4.0, so non-commercial use only unless you have an agreement with Cloudflare. Attribute Cloudflare Radar in every briefing that uses it. Ships off by default (`enabled: false`).
- Verified: 2026-10-20
- Egress hosts: api.cloudflare.com

## What was verified on 20 October 2026

- With a Radar Read token, all six endpoints answered 200: `/annotations/outages`, `/attacks/layer7/summary/{dimension}`, `/bgp/hijacks/events`, `/bgp/leaks/events`, `/ranking/top` and `/ranking/domain/{domain}`.
- `/attacks/layer7/summary` without a dimension answers 400 ("No route for that URI"), so the tool always sends one.
- An unknown domain answers 200 with `rank: null` and bucket `>200000`.
- Test fixtures are synthetic, shaped like those responses, with documentation-range ASNs and prefixes. They carry no Radar data.

## Why a local connector

This connector first wrapped Cloudflare's unified MCP server (`https://mcp.cloudflare.com/mcp?codemode=false`). That did not work in Hermes 0.22.2. The server answers `tools/list` with one 3.6 MB event (3,763 tools), and the MCP client in Hermes refuses events over 1 MiB. Code mode avoids the size limit but exposes a general `execute` tool, which the injection guard treats as a write after any untrusted result. Six read-only tools over the REST API keep the `get_radar_*` names the skills already use, with no write path.

## Operator guide

Read-only internet and attack telemetry from Cloudflare Radar.

**Off by default.** Radar data is CC BY-NC 4.0, so it is for non-commercial use unless you have an agreement with Cloudflare. To turn it on, set `CLOUDFLARE_RADAR_API_TOKEN` in the profile `.env` and `enabled: true` under `mcp_servers.cloudflare_radar` in the profile `config.yaml`. That file is yours: bootstrap and `hermes profile update` keep your choice.

| Question | Tool | Arguments |
|---|---|---|
| AU outages and traffic anomalies | `get_radar_annotations_outages` | `location: AU`, `date_range`, `limit` |
| Layer 7 attacks on AU by mitigation product or method | `get_radar_attacks_layer7_summary` | `dimension`, `location: AU`, `date_range` |
| BGP hijacks involving an Australian ASN | `get_radar_bgp_hijacks_events` | `involved_asn` or `involved_country: AU` |
| BGP route leaks involving an Australian ASN | `get_radar_bgp_leaks_events` | `involved_asn` or `involved_country: AU` |
| Top domains in AU | `get_radar_ranking_top` | `location: AU`, `limit` |
| Rank of a lookalike or suspect domain | `get_radar_ranking_domain` | `domain` |

`date_range` is one of `1d`, `2d`, `7d`, `14d`, `28d`, `12w`, `24w` or `52w`. Results are trimmed to the fields an analyst needs. Outage descriptions, scopes, organisation names and categories are wrapped as untrusted text. A non-https linked URL is dropped.

### Auth

Create the token in the Cloudflare dashboard (or `cf accounts tokens create`) with a single policy: Account > Radar > Read. Set it as `CLOUDFLARE_RADAR_API_TOKEN` in the profile `.env`. A 401 or 403 is reported with the variable name and the token is never echoed.

### Fallback

Responses are cached for 15 minutes. With `CYBERAU_OFFLINE=1`, or when a live fetch fails, a cached copy is served and marked stale. With no cached copy the tool returns no data and a warning. Nothing is shipped with the connector.

`cyberau-mcp health cloudflare-radar --live` is not ok when `CLOUDFLARE_RADAR_API_TOKEN` is unset, because no live call was made. With the token it calls the outages and top ranking endpoints and checks both against `schema/*.response.json`.
