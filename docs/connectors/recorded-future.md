# Recorded Future

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

The optional official MCP entry `recordedfuture_mcp` points at `https://mcp.recordedfuture.com/mcp` with `auth: oauth`, `trust: untrusted` and `enabled: false`. Its `tools.include` list is frozen to read tools. Anything that updates alerts or creates takedowns is excluded.

Suppliers listed under `suppliers` in the org-exposure watchlist are read for `third_party_risk` alerts only. They are not treated as your own organisation.

Upstream reference: https://docs.recordedfuture.com/reference/get-started

Commercial licence. Identity and alert metadata only in the store. No STIX export of vendor content. No sharing outside the profile. Risk lists stay inside the profile.
