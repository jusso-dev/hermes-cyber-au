# cloudflare-urlscanner

- Upstream: https://developers.cloudflare.com/radar/investigate/url-scanner/
- Auth: `CLOUDFLARE_URLSCAN_API_TOKEN` (Account > URL Scanner > Edit) and `CLOUDFLARE_ACCOUNT_ID`. The token is sent as a bearer header and is never logged.
- Rate limit: one URL at a time. After a burst of 4, at most one request every 10 seconds, which stays under Cloudflare's client API limits and the 10 to 30 second poll guidance.
- Terms: Scans default to Public on Cloudflare's side and appear in the recent scans list, so an internal URL could be published. This connector always sends Unlisted. Submitting a scan needs a person's one-time approval token. Doctor lists this connector as off by default: licence terms (docs/connectors/cloudflare-urlscanner.md).
- Verified: 2026-10-16
- Egress hosts: api.cloudflare.com
- Default: off. A fresh install renders `enabled: false` even when both variables are set. A profile update keeps the user's `enabled` flag.
