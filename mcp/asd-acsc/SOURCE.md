# asd-acsc

- Upstream: https://www.cyber.gov.au/rss/alerts and the advisories, publications, threats and news RSS paths. One directory also lists news under /acsc/view-all-content/news/rss. That alternate path was not verified from this host.
- Auth: none
- Rate limit: one feed poll per 10 minutes, with one extra request allowed for the HTTP/1.1 fallback. Item pages at most one request every 5 seconds. Timeout 60 seconds, 3 retries.
- Terms: Commonwealth of Australia material from ASD's ACSC. The copyright page could not be fetched on 17 October 2026, so the licence wording is not copied here. Confirm https://www.cyber.gov.au/about-us/copyright before reuse. This connector is not endorsed by ASD.
- Verified: 2026-10-17
- Egress hosts: www.cyber.gov.au

## Runtime fetch on 17 October 2026

From this Mac, `https://www.cyber.gov.au/rss/alerts` failed before any bytes arrived.

- HTTP/2: curl exit 92, stream was not closed cleanly (INTERNAL_ERROR).
- HTTP/1.1 with a project User-Agent and an XML Accept header: curl exit 28, timeout after 40 seconds, 0 bytes.

The connector therefore keeps a synthetic shipped snapshot for offline tests and a manual import path. A live health check from a network that can reach cyber.gov.au is still required before treating the feed as current. The fallback ladder is direct fetch, then HTTP/1.1 with browser-like headers that still include `hermes-cyber-au` in the User-Agent, then the last stored poll, then the shipped snapshot.

Items are stored in `$CYBERAU_DATA_DIR/asd_advisories.sqlite` (table `advisories`, id `asd:<feed>:<sha1(link)>`) until the shared intel store exists. Rows are not deleted when they leave the rolling RSS window.
