# abuseipdb

- Upstream: https://docs.abuseipdb.com/
- Auth: `Key` header from `ABUSEIPDB_API_KEY`. Never logged.
- Rate limit: Free Individual plan ceiling is 1,000 checks a day and 100 block checks a day. This connector stays under that at 900 checks a day and 80 block checks a day.
- Terms: Terms not confirmed. Check the AbuseIPDB terms before release. Attribute AbuseIPDB.
- Verified: 2026-10-16
- Egress hosts: api.abuseipdb.com

## Operator guide

Read-only IP reputation from the AbuseIPDB API. Reporting an address is not implemented.

| Tool | What it returns |
|---|---|
| `abuseipdb_check_ip` | Confidence score, report count, ISP, usage type and country for one public IP |
| `abuseipdb_check_block` | Reported addresses in a public CIDR, at most a /24 on the free plan |

`ABUSEIPDB_API_KEY` is required for a live check. It is sent as the `Key` header and is never logged. Private and reserved addresses are refused before any network call.

The free plan allows 1,000 checks a day and 100 block checks a day. This connector stays under that, at 900 checks a day and 80 block checks a day. Successful checks are cached for 6 hours. Score changes are appended under the data directory so a later refresh can show the history.

ISP, usage type, domain and other free-text fields are returned as untrusted text.

AbuseIPDB (https://www.abuseipdb.com/). This product is not endorsed by AbuseIPDB. Terms were not confirmed at build time; check them before release.
