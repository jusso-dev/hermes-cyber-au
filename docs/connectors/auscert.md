# AusCERT public security bulletins

Read-only access to the public AusCERT security bulletin RSS (External Security Bulletins and AusCERT Security Bulletins).

| Tool | What it returns |
|---|---|
| `auscert_bulletins` | Recent bulletins, newest first, optionally filtered by `since` (a date in Australia/Sydney), a keyword or a CVE id |

Each record carries the bulletin id, title, link, published time in Australia/Sydney, the feed summary, the highest CVSS score named in the title, and the CVE ids found in the bulletin. The bulletin text itself is never returned or stored. Titles and summaries are untrusted and arrive wrapped in untrusted markers.

No API key and no env var. The feed is fetched at most once every 30 minutes, with a conditional GET, and a `429` response is honoured through its `Retry-After` header. The path `https://www.auscert.org.au/rss/bulletins/` returns a 404 page, so the connector uses `https://portal.auscert.org.au/rss/bulletins/`. If AusCERT cannot be reached, the last cached feed is served and marked `stale`. With `CYBERAU_OFFLINE=1` the connector answers from the cache, then from a small synthetic snapshot.

Many bulletins repeat vendor advisories, so deduplicate by CVE id in the intel store. Every poll is recorded in `$CYBERAU_DATA_DIR/auscert_bulletins.sqlite`, so bulletins that leave the rolling feed are kept.

Bulletins are published by AusCERT. This connector is not endorsed by AusCERT, and member-only portal content is out of scope.
