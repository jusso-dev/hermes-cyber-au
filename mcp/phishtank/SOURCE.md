# phishtank

- Upstream: https://phishtank.org/developer_info.php
- Auth: optional `PHISHTANK_APP_KEY`, sent only as a path segment on the database URL. Never logged, stored in the envelope, or written into fixtures.
- Rate limit: one database download an hour. A 429 is retried once, and only when `Retry-After` is 60 seconds or less. A longer wait is reported as a rate limit, with a cached copy served (labelled stale) when one exists. The download never blocks waiting for the hourly limit. Without an application key, PhishTank allows only a few downloads a day.
- Terms: Licence not confirmed. Cite PhishTank. This connector is not endorsed by PhishTank or Cisco Talos.
- Verified: 2026-10-17
- Egress hosts: data.phishtank.com, cdn.phishtank.com

The developer page lists the database as HTTP. This connector uses HTTPS. On 17 October 2026 the database URL answered 302 to `cdn.phishtank.com` and that host returned `verified_online.json` as `application/json`. Cloudflare caches the redirect for longer than the signed URL stays valid, so each download sends a nonce query and follows the fresh redirect at once. The signature query is not copied into the envelope.

`phishtank_check_url` compares the URL with the cached verified-online set. It does not request that URL.

Records are stored in `$CYBERAU_DATA_DIR/phishtank.sqlite` (table `phish`, id `phish_id`) until the shared intel store exists. Rows are not deleted when they leave the hourly online-valid set.

Fallback ladder: a fresh download, then the cached copy (labelled stale when older than an hour, or when served after a failed or rate-limited download), then unavailable. When neither a download nor a cached copy is available, `phishtank_check_url` returns empty data with `cache: snapshot` and an "is unavailable" warning. No snapshot ships with the connector. Treat an unavailable result as unknown, not clean.

`CYBERAU_PHISHTANK_SNAPSHOT` may point at an operator-supplied `online-valid.json`. It is read only when set, served with `cache: snapshot` and a warning that it came from that file rather than a live download, and never written to the intel store. The offline schema check reads that file or the cached copy, and reports ok with "no local copy to check" when neither exists. Synthetic test data lives under `tests/fixtures/` and is never served at runtime.

## Operator guide

Read-only check against the PhishTank verified-online database.

| Tool | What it returns |
|---|---|
| `phishtank_check_url` | Whether a URL is in the cached verified-online set, with the normalised PhishTank record |

The connector downloads `online-valid.json` at most once an hour, follows PhishTank's CDN redirect, and compares the URL locally. It does not request the URL under test. An optional `PHISHTANK_APP_KEY` is placed in the download path and raises the daily allowance. Without a key, PhishTank allows only a few downloads a day. The target name is untrusted text.

PhishTank is operated by Cisco Talos. Licence not confirmed. This connector is not endorsed by PhishTank.
