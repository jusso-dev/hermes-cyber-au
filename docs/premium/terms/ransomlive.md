# ransomware.live victim tracker (free, filter by country AU)

Server `ransomlive`. Free feed. It still ships disabled because it handles victim claims.

Generated from `mcp/premium/vendors.yaml`. Not legal advice.

## Terms

| Flag | Default |
| --- | --- |
| `cache` | `ttl` |
| `cache_ttl_max_s` | `3600` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

## Licence environment

Names only. Put values in the profile `.env`. Do not commit them.

- No required licence variable.
- `RANSOMWARE_LIVE_API_KEY` (optional)

## Quota defaults

- Calls per day: 24
- Calls per month: 500000
- Cost units per call: 1
- Monthly budget units: not set (you set this)
- Approval above units: not set
- Hard stop: true
- Routine share: 0.5
- Max pages: 5

## Attribution

Free community project. Victim entries are unverified claims from criminal leak sites. Cache at most 1 hour. Store metadata only. No STIX export of victim names.
