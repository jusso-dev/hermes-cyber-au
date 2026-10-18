# recorded-future

- Upstream: https://docs.recordedfuture.com/reference/get-started
- Auth: `X-RFToken` from `RECORDED_FUTURE_API_TOKEN`. Optional `RECORDED_FUTURE_ORG_ID` is sent as `organization_id` when a token covers more than one organisation. The official MCP server uses OAuth (`RECORDED_FUTURE_MCP_CLIENT_ID` and `RECORDED_FUTURE_MCP_CLIENT_SECRET`). Never logged.
- Rate limit: one Daily API Call Limit per subscription, shared by REST and MCP (one MCP tool call counts as one API call). The user sets that limit in config. Back off on 429 and honour `Retry-After`.
- Terms: Commercial licence. Bring your own licence. The server ships off. Identity and alert metadata only in the store. No STIX export of vendor content. No sharing outside the profile. Risk lists stay inside the profile. MCP access needs a subscription with unlimited integrations (pilot access for others runs to 31 December 2026, per the vendor). See `docs/connectors/recorded-future.md`.
- Verified: 2026-10-17 against docs.recordedfuture.com (Identity search, detections and lookup OpenAPI; Playbook Alerts search, where the dark web brand category is `dark_web`, and the `dark_web_brand`, `domain_abuse` and `identity_novel_exposures` detail operations; Connect API company by domain). Stat checks are `HEAD` on `/v2/{ip|domain|hash|url|vulnerability}/risklist` with the `list` query (ETag, including 304). A bad token returns 401. `mcp.recordedfuture.com/mcp` answers 401 without auth. Official MCP tool names were frozen from the vendor support article "Recorded Future MCP: Available Tools" (17 October 2026). Suppliers are read from `suppliers` in the org-exposure watchlist file and never treated as the caller's own organisation.
- Egress hosts: api.recordedfuture.com, mcp.recordedfuture.com

## Operator guide

Read-only identity exposure, dark web and ransomware brand alerts, domain abuse, company risk and risk-list status. The server ships disabled. You bring your own licence. Nothing in this connector submits, updates an alert or requests a takedown.

Before the first Recorded Future call in a session, state these terms: commercial licence; identity and alert metadata only in the store; no STIX export of vendor content; no sharing outside the profile; risk lists stay inside the profile. MCP access needs a subscription with unlimited integrations (pilot access for others runs to 31 December 2026, per the vendor).

`doctor` lists the connector as off until you set `enabled: true` in your profile `config.yaml`. While it is off, the official MCP line is: off by default: licence terms (docs/connectors/recorded-future.md). When it is on, `doctor` reports the connected organisation from the `whoami` tool.

| Tool | What it returns |
|---|---|
| `rf_identity_exposure` | Counts of compromised identities for watchlist domains. No passwords, cookies or usernames |
| `rf_identity_detections` | Novel identity detections grouped by domain and malware family |
| `rf_identity_lookup_hashed` | Exposure history for SHA1 hashes of email addresses. Plain email is refused |
| `rf_brand_alerts` | Dark web brand and domain abuse playbook alerts, matched to the watchlist |
| `rf_alert_detail` | Detail panels for one playbook alert. Screenshots are not fetched |
| `rf_company_by_domain` | Company entity, risk score and top triggered rules |
| `rf_risklist_status` | Whether a risk list changed since the last stat check |

Set `RECORDED_FUTURE_API_TOKEN` in the profile `.env`. Optional: `RECORDED_FUTURE_ORG_ID`, `RECORDED_FUTURE_MCP_CLIENT_ID`, `RECORDED_FUTURE_MCP_CLIENT_SECRET`. A present key does not enable the server. Bootstrap and profile update leave `enabled: false` until you turn it on.

The connector also checks `mcp_servers.recordedfuture.enabled` in the profile `config.yaml` before every upstream call, and counts each call against your quota. If that file is missing or `enabled` is not `true`, every call is refused. Domain inputs must be on the org-exposure watchlist. With no watchlist they are refused unless `CYBERAU_RF_ALLOW_EXTERNAL=1`.

Fallback ladder: live call, then the response cached earlier, then unavailable. When none of those has data, a tool returns empty data and an "is unavailable" warning. No snapshot ships with the package. Synthetic samples live under `tests/fixtures/` and are read only by the offline schema check (`health --check-schema` without `--live`). `CYBERAU_RF_SCHEMA_FIXTURE` points that check at another file.

`cyberau-mcp health recorded-future --live` fails when the token is missing, when a call fails, or when the answer came from a cached or snapshot copy.

The optional official MCP entry `recordedfuture_mcp` points at `https://mcp.recordedfuture.com/mcp` with `auth: oauth`, `trust: untrusted` and `enabled: false`. Its `tools.include` list is frozen to read tools. Anything that updates alerts or creates takedowns is excluded.

Suppliers listed under `suppliers` in the org-exposure watchlist are read for `third_party_risk` alerts only. They are not treated as your own organisation.

Upstream reference: https://docs.recordedfuture.com/reference/get-started

Commercial licence. Identity and alert metadata only in the store. No STIX export of vendor content. No sharing outside the profile. Risk lists stay inside the profile.
