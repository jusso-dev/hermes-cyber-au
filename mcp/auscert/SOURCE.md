# auscert

- Upstream: https://portal.auscert.org.au/rss/bulletins/ (the old https://www.auscert.org.au/rss/bulletins/ path returns a 404 page)
- Auth: none. Member-only portal content is out of scope.
- Rate limit: one request per 30 minutes, no automatic retries. A `429` pauses the connector for the `Retry-After` period, between 1 and 60 minutes. Timeout 60 seconds.
- Terms: return title, link, date and the feed summary only. Do not mirror full bulletins. AusCERT's terms were not checked for snapshotting, so the shipped snapshot and every fixture are synthetic. Confirm https://www.auscert.org.au/ before reuse. This connector is not endorsed by AusCERT.
- Verified: 2026-10-17
- Egress hosts: portal.auscert.org.au

## Live feed on 17 October 2026

`GET https://portal.auscert.org.au/rss/bulletins/` returned HTTP 200, `application/rss+xml; charset=utf-8`, about 1.8 MB, with `Last-Modified` set and `Cache-Control: max-age=300`. It held 100 items, all `ESB` bulletins. Each item has `title`, `link`, `description`, `pubDate`, `guid` and a `content:encoded` element holding the full bulletin text.

- `description` was a single space on every item, so the summary is usually empty.
- Titles read `<product>: CVSS (Max): <score>`.
- Links and guids use `http://`, and the connector returns `https://` links.
- The CVE ids come from the `CVE Names` lines in `content:encoded`. The connector reads that element to find CVE ids and never returns or stores it.

## Local storage

- The shared HTTP cache in `$CYBERAU_DATA_DIR/http_cache.sqlite` keeps the whole response for conditional requests and stale fallback. It stays in the profile data directory and is never returned or republished.
- Normalised records (id, title, link, published time, summary, CVE ids) are kept in `$CYBERAU_DATA_DIR/auscert_bulletins.sqlite` (table `bulletins`, keyed by bulletin id) until the shared intel store exists. Rows are not deleted when they leave the rolling feed.
- A `429` writes its pause to `$CYBERAU_DATA_DIR/auscert_backoff.json`.

## Operator guide

Read-only access to the public AusCERT security bulletin RSS (External Security Bulletins and AusCERT Security Bulletins).

| Tool | What it returns |
|---|---|
| `auscert_bulletins` | Recent bulletins, newest first, optionally filtered by `since` (a date in Australia/Sydney), a keyword or a CVE id |

Each record carries the bulletin id, title, link, published time in Australia/Sydney, the feed summary, the highest CVSS score named in the title, and the CVE ids found in the bulletin. The bulletin text itself is never returned or stored. Titles and summaries are untrusted and arrive wrapped in untrusted markers.

No API key and no env var. The feed is fetched at most once every 30 minutes, with a conditional GET, and a `429` response is honoured through its `Retry-After` header. The path `https://www.auscert.org.au/rss/bulletins/` returns a 404 page, so the connector uses `https://portal.auscert.org.au/rss/bulletins/`. If AusCERT cannot be reached, the last cached feed is served and marked `stale`. With `CYBERAU_OFFLINE=1` the connector answers from the cache, then from a small synthetic snapshot.

Many bulletins repeat vendor advisories, so deduplicate by CVE id in the intel store. Every poll is recorded in `$CYBERAU_DATA_DIR/auscert_bulletins.sqlite`, so bulletins that leave the rolling feed are kept.

Bulletins are published by AusCERT. This connector is not endorsed by AusCERT, and member-only portal content is out of scope.
