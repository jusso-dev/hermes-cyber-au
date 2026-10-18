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

Fallback ladder: live feed, then the last cached copy, then unavailable. No feed file ships with the package. When neither the live feed nor a cached copy can be used (offline with no cache, a failed fetch, a refused redirect, a non-feed body or the hourly limit), the answer carries `cache: snapshot`, no OpenPhish row, and a warning saying the OpenPhish feed is unavailable. If no PhishTank or URLhaus cache is usable either, `data` is empty.

`CYBERAU_OPENPHISH_SNAPSHOT` may name an operator-supplied feed file. An answer from it carries `cache: snapshot` and a warning that it came from a pinned snapshot file, not live data, and it is not written to `openphish.sqlite`. Test fixtures, including the synthetic `phish.example` feed, live under `tests/fixtures/` and are never served at runtime. The offline schema check reads the pinned file or the cached copy, and reports ok with "no local copy to check" when there is neither. Live health ignores the pinned file, the offline flag, the cache and the hourly fallback, so a failed fetch, a timeout, a non-feed body or an exhausted hourly limit reports not ok.

## Operator guide

Read-only check of one URL against the OpenPhish community feed, together with any PhishTank and URLhaus caches already on disk. The connector never requests the URL under test.

| Tool | What it returns |
|---|---|
| `phish_check_url` | Whether that URL is in the OpenPhish feed, the PhishTank cache, and the URLhaus cache |

No API key. The feed is fetched at most once an hour from `https://openphish.com/feed.txt`. On 17 October 2026 that address redirected to the OpenPhish public feed on `raw.githubusercontent.com`. Redirects to any other host are refused.

When neither the live feed nor a cached copy can be used, the result is labelled `snapshot` with a warning that the OpenPhish feed is unavailable, and no OpenPhish row is returned. No sample feed is ever served in its place. A pinned file named by `CYBERAU_OPENPHISH_SNAPSHOT` is labelled as such and is never written to the history store. Lines from the feed are untrusted text. An empty feed does not wipe a previous cache. Licence not confirmed. The community feed is a small sample. This connector is not affiliated with OpenPhish.
