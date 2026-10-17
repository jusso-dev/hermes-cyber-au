# google-ti-dtm

- Upstream: https://gtidocs.virustotal.com/
- Auth: `GTI_API_KEY` as the `x-apikey` header, plus `x-tool: jusso-dev.hermes-cyber-au.0.1`. Never log the key. Do not reuse a VirusTotal Public API key.
- Rate limit: Per licence. This client stays at 1 request per second, burst 5, and backs off on HTTP 429 using Retry-After.
- Terms: Commercial licence. Session cache. Store metadata only. No STIX export. Redistribution forbidden. See docs/connectors/google-ti-dtm.md.
- Verified: 2026-10-16
- Egress hosts: www.virustotal.com
