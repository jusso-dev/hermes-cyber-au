# Google Threat Intelligence Digital Threat Monitoring (formerly Mandiant)

Server `gtidtm`. Paid, bring your own licence. The server ships disabled.

Generated from `mcp/premium/vendors.yaml`. Not legal advice.

## Terms

| Flag | Default |
| --- | --- |
| `cache` | `session` |
| `cache_ttl_max_s` | `0` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

## Licence environment

Names only. Put values in the profile `.env`. Do not commit them.

- `GTI_API_KEY` (required)

## Quota defaults

- Calls per day: not set
- Calls per month: not set
- Cost units per call: 1
- Monthly budget units: not set (you set this)
- Approval above units: not set
- Hard stop: true
- Routine share: 0.5
- Max pages: 5

## Attribution

Commercial licence. Session cache. Store metadata only. No STIX export. Do not reuse a VirusTotal Public API key.
