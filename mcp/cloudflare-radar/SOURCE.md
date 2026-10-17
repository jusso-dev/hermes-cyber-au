# cloudflare-radar

- Upstream: Cloudflare's unified MCP server (https://github.com/cloudflare/mcp) at https://mcp.cloudflare.com/mcp?codemode=false, Radar tools only. The deprecated dedicated Radar MCP server (`cloudflare/mcp-server-cloudflare`, `apps/radar`) is not used. Underlying API: https://developers.cloudflare.com/radar/
- Auth: OAuth 2.1 through the Hermes MCP client, or a custom API token with only Account > Radar > Read sent as `Authorization: Bearer ${CLOUDFLARE_RADAR_API_TOKEN}`. The upstream README lists both. Tokens with Client IP Address Filtering are not supported upstream.
- Rate limit: Cloudflare client API allows 1,200 requests per 5 minutes per token. Going over blocks calls for 5 minutes, so read `retry-after`. The `radar-au` skill budgets calls well under this.
- Terms: Cloudflare Radar API data is CC BY-NC 4.0, so non-commercial use only unless you have an agreement with Cloudflare. Attribute Cloudflare Radar in every briefing that uses it. Ships off by default (`enabled: false`).
- Verified: 2026-10-17
- Egress hosts: mcp.cloudflare.com

## What was and was not verified on 17 October 2026

- `https://mcp.cloudflare.com/mcp?codemode=false` answered 401 to an unauthenticated `tools/list`, so it exists.
- The upstream README says `?codemode=false` registers one tool per API endpoint, and that a bearer API token works as well as OAuth.
- The Hermes catalogue entry at commit 43faacf excludes `*_radar_*` by default and describes about 275 Radar tools.
- Not verified: the real tool names and the live Radar responses. No token was available. `tests/fixtures/tools_list_radar.json` and the response fixtures are synthetic stand-ins shaped like the Radar API, with documentation-range ASNs and prefixes, and carry no real data. `expected_tools.txt` pins only the five tools the skill uses. Record a real `tools/list` and regenerate both before relying on the filter.

## Layout

A wrap has no local server code.

- `mcp/servers.yaml` entry `cloudflare_radar` (`kind: wrap`) is rendered into Hermes `mcp_servers` by `cyberau_common.wrap.render_entry`.
- `probe.json` lists one cheap call per tool group for `cyberau-mcp health cloudflare-radar --live`. Each response is checked against `schema/*.response.json`. Without `CLOUDFLARE_RADAR_API_TOKEN`, or with `CYBERAU_OFFLINE` set, the live probe is not run and reports not ok.
- `wrap_result` wraps upstream results in the shared envelope. Hermes connects to the upstream directly, so it is not on the live path yet; only `trust: untrusted` applies there.
- `expected_tools.txt` is the pinned filtered tool list. A change is reported as drift by the health check.
