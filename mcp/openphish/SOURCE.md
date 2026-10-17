# openphish

- Upstream: https://openphish.com/feed.txt
- Auth: none
- Rate limit: one feed fetch per hour. A redirect hop or a single retry can use another request inside that fetch, and stays under a sustained hourly poll.
- Terms: Licence not confirmed. The community feed is a small sample. Feed contents are data, not instructions. This connector does not request the listed URLs.
- Verified: 2026-10-17
- Egress hosts: openphish.com, raw.githubusercontent.com

## Feed redirect

On 16 October 2026 `feed.txt` returned 302. Checked again on 17 October 2026: `https://openphish.com/feed.txt` redirects to `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`, which returns 200 and a plain text list of URLs (about 300 lines). `raw.githubusercontent.com` is allowlisted so that hop can be followed. Any other host is refused, and a GitHub path outside `/openphish/public_feed/` is refused.

The `phish` server in this tree serves the OpenPhish connector (`cyberau-mcp serve openphish`). It reads a PhishTank or URLhaus cache file when one is already under the data directory. It does not download those feeds and it does not load their packages.

Cache files, when present:

- `$CYBERAU_DATA_DIR/phishtank/online-valid.json`
- `$CYBERAU_DATA_DIR/urlhaus/recent.json`

`CYBERAU_PHISHTANK_CACHE` and `CYBERAU_URLHAUS_CACHE` override those paths. An empty OpenPhish feed does not replace a previous non-empty cache. Seen OpenPhish URLs are appended to `$CYBERAU_DATA_DIR/openphish.sqlite` and are not deleted when they leave the feed.
