# Recorded Future (identity exposure, dark web and brand alerts)

Server `recordedfuture`. Paid, bring your own licence. The server ships disabled.

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

- `RECORDED_FUTURE_API_TOKEN` (required)
- `RECORDED_FUTURE_ORG_ID` (optional)
- `RECORDED_FUTURE_MCP_CLIENT_ID` (optional)
- `RECORDED_FUTURE_MCP_CLIENT_SECRET` (optional)

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

Commercial licence. Identity and alert metadata only in the store. No STIX export of vendor content. No sharing outside the profile. Risk lists stay inside the profile.
