# phishtank

- Upstream: https://phishtank.org/developer_info.php
- Auth: optional `PHISHTANK_APP_KEY`, sent only as a path segment on the database URL. Never logged, stored in the envelope, or written into fixtures.
- Rate limit: one database download an hour. A 429 waits for `Retry-After` inside that same download. Without an application key, PhishTank allows only a few downloads a day.
- Terms: Licence not confirmed. Cite PhishTank. This connector is not endorsed by PhishTank or Cisco Talos.
- Verified: 2026-10-17
- Egress hosts: data.phishtank.com, cdn.phishtank.com

The developer page lists the database as HTTP. This connector uses HTTPS. On 17 October 2026 the database URL answered 302 to `cdn.phishtank.com` and that host returned `verified_online.json` as `application/json`. Cloudflare caches the redirect for longer than the signed URL stays valid, so each download sends a nonce query and follows the fresh redirect at once. The signature query is not copied into the envelope.

`phishtank_check_url` compares the URL with the cached verified-online set. It does not request that URL.

Records are stored in `$CYBERAU_DATA_DIR/phishtank.sqlite` (table `phish`, id `phish_id`) until the shared intel store exists. Rows are not deleted when they leave the hourly online-valid set.
