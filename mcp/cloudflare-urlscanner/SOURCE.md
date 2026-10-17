# cloudflare-urlscanner

- Upstream: https://developers.cloudflare.com/radar/investigate/url-scanner/
- Auth: `CLOUDFLARE_URLSCAN_API_TOKEN` (Account > URL Scanner > Edit) and `CLOUDFLARE_ACCOUNT_ID`. The token is sent as a bearer header and is never logged.
- Rate limit: one URL at a time. After a burst of 4, at most one request every 10 seconds, which stays under Cloudflare's client API limits and the 10 to 30 second poll guidance.
- Terms: Scans default to Public on Cloudflare's side and appear in the recent scans list, so an internal URL could be published. This connector always sends Unlisted. Submitting a scan needs a person's one-time approval token. Doctor lists this connector as off by default: licence terms (docs/connectors/cloudflare-urlscanner.md).
- Verified: 2026-10-16
- Egress hosts: api.cloudflare.com
- Default: off. A fresh install renders `enabled: false` even when both variables are set. A profile update keeps the user's `enabled` flag.

## Operator guide

Read-only lookups, plus an approval-gated Unlisted scan, for the Cloudflare URL Scanner API.

| Tool | What it returns |
|---|---|
| `urlscan_submit_unlisted` | Submits one URL with visibility Unlisted, after a person approves that exact URL |
| `urlscan_get_result` | Verdict, final URL, contacted IPs and ASNs for one scan |

The server name is `cfscan`. It ships disabled. Doctor reports it as off by default: licence terms.

### Terms

Scans default to Public on Cloudflare's side and appear in the recent scans list, so an internal URL could be published. This connector always sends Unlisted.

Successful scans are kept by Cloudflare for 12 months. Failed scans older than 30 days are deleted. This product is not affiliated with Cloudflare.

A skill that calls this connector states those terms before the first call in a session:

> Cloudflare URL Scanner publishes scans as Public unless the request says Unlisted. An internal URL in a Public scan can appear in the recent scans list. This connector only submits Unlisted scans, and only after you approve that exact URL.

### Approval

Submitting a scan is a write to Cloudflare. `urlscan_submit_unlisted` refuses the call before any network request unless `approval_token` was issued for that exact URL. A token lasts 15 minutes, works once, and is not sent to Cloudflare. Issue it in the profile after the person has approved the URL:

```python
from cyberau_cloudflare_urlscanner.source import issue_unlisted_approval

issue_unlisted_approval("https://example.com/login")
```

There is no parameter that can change visibility. If Cloudflare reports anything other than Unlisted, the tool returns a warning and no record that claims the scan was Unlisted.

### Turn it on

Set `CLOUDFLARE_URLSCAN_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` in the profile `.env`. The token needs Account > URL Scanner > Edit and should not be reused for other Cloudflare APIs.

A fresh install still renders `enabled: false` under `mcp_servers.cfscan` when those variables are set. Turn the server on with `enabled: true` in the profile `config.yaml`. `hermes profile update` keeps that choice and does not switch the server back on or off.

Polling a result that is not finished returns HTTP 404. Wait 10 to 30 seconds and call `urlscan_get_result` again. Page titles and verdict categories are untrusted text.
