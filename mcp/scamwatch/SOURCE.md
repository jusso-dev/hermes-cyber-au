# scamwatch

- Upstream: https://www.scamwatch.gov.au/
- Auth: none
- Rate limit: one homepage or alert request every 6 hours. A 429 may retry once inside that same poll, honouring `Retry-After`.
- Terms: Licence not confirmed. Quote short passages with attribution. This connector is not endorsed by the ACCC or Scamwatch.
- Verified: 2026-10-17
- Egress hosts: www.scamwatch.gov.au

## What this connector reads

The homepage has a News and alerts section. Each alert is a link under `/about-us/news-and-alerts/<slug>` with a title and, when the page includes one, a date. `scamwatch_get_alert` reads one of those pages and returns cleaned text. The embedded Power BI statistics report is out of scope.

The connector is read-only. It does not submit a scam report, and it does not contact a person who reported a scam or the ACCC.

## Blocked clients

From this host on 17 October 2026, a direct GET of the homepage returned 403 Access Denied (Akamai). A separate fetch the same day returned the page, including the News and alerts section. A 401, a 403, or an access-denied body is reported as blocked. It is not treated as an empty alert list. When a previous copy is cached, that copy is returned with the blocked warning.

## Offline copy

Items are kept in `$CYBERAU_DATA_DIR/scamwatch.sqlite` (table `alerts`) until the shared intel store exists. A change in title, date, summary, or body is also appended to `$CYBERAU_DATA_DIR/scamwatch-alerts.jsonl`. Rows are not deleted when they leave the homepage. Offline mode answers from the HTTP cache, then the shipped synthetic snapshot, and otherwise returns an unavailable warning.
