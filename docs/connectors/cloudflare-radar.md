# Cloudflare Radar via Cloudflare's unified MCP server

Read-only internet and attack telemetry from Cloudflare Radar. This connector wraps Cloudflare's own unified MCP server at `https://mcp.cloudflare.com/mcp?codemode=false`. There is no local server code. It exposes only tools matching `*_radar_*`, and every one of them is a GET endpoint. It does not use the deprecated dedicated Radar MCP server.

**Off by default.** Radar data is CC BY-NC 4.0, so it is for non-commercial use unless you have an agreement with Cloudflare. `cyberau-mcp health cloudflare-radar` reports "off by default: licence terms" and points here. To turn it on, set `enabled: true` under `mcp_servers.cloudflare_radar` in your profile `config.yaml`. That file is yours: `hermes profile update` keeps your choice, and bootstrap never switches it on.

| Question | Tool |
|---|---|
| Layer 7 attack summary for AU | `get_radar_attacks_layer7_summary` |
| AU outages and traffic anomalies | `get_radar_annotations_outages` |
| BGP hijacks and leaks for an Australian ASN | `get_radar_bgp_hijacks_events`, `get_radar_bgp_leaks_events` |
| Domain rank for lookalike triage | `get_radar_ranking_top` |

Tool names in this table are those pinned in `mcp/cloudflare-radar/expected_tools.txt`. They have not yet been confirmed against a live `tools/list`; see `mcp/cloudflare-radar/SOURCE.md`. The `radar-au` skill covers question patterns, the call budget and attribution.

## Auth

Either sign in with OAuth 2.1 on first connect (the default, scope the grant to Radar read), or set `CLOUDFLARE_RADAR_API_TOKEN` in the profile `.env` to a custom token with only Account > Radar > Read. With the token set, the rendered config sends `Authorization: Bearer ${CLOUDFLARE_RADAR_API_TOKEN}` and has no `auth` key.

## Limits

Cloudflare allows 1,200 requests per 5 minutes per token, and going over blocks calls for 5 minutes. Results are capped near 6,000 tokens each. Radar free text is untrusted.

Data: Cloudflare Radar, CC BY-NC 4.0. Attribute Cloudflare Radar in every briefing that uses it. This connector is not endorsed by Cloudflare.
