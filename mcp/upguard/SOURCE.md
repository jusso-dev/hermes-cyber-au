# upguard

- Upstream: https://cyber-risk.upguard.com/api/docs
- Auth: `UPGUARD_API_KEY` as the `Authorization` header value, with no Bearer prefix. Read permissions only (`IdentityBreaches`, `DataLeaks`, `BreachRisk`). Never logged.
- Rate limit: 429 is documented and no number is published. Back off on 429. Local ceiling is 30 requests a minute.
- Terms: Commercial licence. Cache typosquat lists at most 12 hours. Breach and data leak records use a session cache. Store metadata only. No STIX export. No sharing outside the profile. Read-only: this connector does not call the disclosure status update.
- Verified: 2026-10-17
- Egress hosts: cyber-risk.upguard.com

## Operator guide

Read-only identity breaches, data leak disclosures and typosquat domains from UpGuard CyberRisk. Paid, bring your own licence. The server ships disabled (`enabled: false`). Bootstrap leaves it disabled even when `UPGUARD_API_KEY` is set. You turn it on with `enabled: true` in your profile `config.yaml`, which `hermes profile update` keeps.

Doctor lists it as off (paid, bring your own licence) until then. This page quotes the terms.

Generated from `mcp/upguard/SOURCE.md`, `mcp/premium/vendors.yaml` and the tool schemas. Not legal advice.

| Tool | What it returns |
|---|---|
| `upguard_identity_breaches` | Breach name, date and data classes for the account's domains. No credential values and no identity names. |
| `upguard_data_leaks` | Data leak disclosures in a time window, with status. Payloads and images are not returned. |
| `upguard_typosquats` | Lookalike domains for one enabled domain. Each finding records the watched domain it relates to. |

`UPGUARD_API_KEY` is sent as the `Authorization` header value, with no `Bearer` prefix. Create the key with read permissions only (`IdentityBreaches`, `DataLeaks`, `BreachRisk`). This connector does not call the disclosure status update.

Typosquat lists are cached for at most 12 hours. Breach and data leak records stay in a session cache and are not written to the HTTP disk cache. Stored findings are metadata only.

### Terms

Commercial licence. Cache at most 12 hours. Store metadata only. No STIX export unless your own contract allows it. No sharing outside the profile.

| Flag | Default |
|---|---|
| `cache` | `ttl` |
| `cache_ttl_max_s` | `43200` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

Typosquat domains are your own monitoring results. Export stays off until you relax `stix_export` with a contract reference. The tool text states these terms before a call.

Upstream: https://cyber-risk.upguard.com/api/docs (API 1.12). Egress host: `cyber-risk.upguard.com`.
