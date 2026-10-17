# upguard

- Upstream: https://cyber-risk.upguard.com/api/docs
- Auth: `UPGUARD_API_KEY` as the `Authorization` header value, with no Bearer prefix. Read permissions only (`IdentityBreaches`, `DataLeaks`, `BreachRisk`). Never logged.
- Rate limit: 429 is documented and no number is published. Back off on 429. Local ceiling is 30 requests a minute.
- Terms: Commercial licence. Cache typosquat lists at most 12 hours. Breach and data leak records use a session cache. Store metadata only. No STIX export. No sharing outside the profile. Read-only: this connector does not call the disclosure status update.
- Verified: 2026-10-17
- Egress hosts: cyber-risk.upguard.com
