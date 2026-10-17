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

The bundled `data/online-valid.json` is synthetic. It is served only offline with no cache, with `cache: snapshot` and a warning, and is never written to the intel store. A cached copy older than an hour, or one served after a failed or rate-limited download, carries a warning.

## Operator guide

Read-only check against the PhishTank verified-online database.

| Tool | What it returns |
|---|---|
| `phishtank_check_url` | Whether a URL is in the cached verified-online set, with the normalised PhishTank record |

The connector downloads `online-valid.json` at most once an hour, follows PhishTank's CDN redirect, and compares the URL locally. It does not request the URL under test. An optional `PHISHTANK_APP_KEY` is placed in the download path and raises the daily allowance. Without a key, PhishTank allows only a few downloads a day. The target name is untrusted text.

PhishTank is operated by Cisco Talos. Licence not confirmed. This connector is not endorsed by PhishTank.
