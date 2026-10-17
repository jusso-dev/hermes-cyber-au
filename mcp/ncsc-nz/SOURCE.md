# ncsc-nz

- Upstream: https://www.ncsc.govt.nz/alerts/ HTML list (`?start=N`, 12 alerts a page). No RSS. cert.govt.nz redirects here.
- Auth: none
- Rate limit: one list page per hour. Alert pages at most one request every 5 seconds.
- Terms: Licence not confirmed. Return title, date, link and extracted CVEs. Quote short passages only. This connector is not endorsed by the NCSC.
- Verified: 2026-10-16 the alerts page returned 200 from the build box. On 2026-10-17 live health returned ok from this host over HTTP/1.1 and the first page parsed to 12 alerts. An HTTP/2 GET from this host received a bot-check 403.
- Egress hosts: www.ncsc.govt.nz

The list selectors the schema check requires are `explore--alert` or `card--alert`, and on each card `card__link`, `card__title` and `card__date`. Alerts whose titles start with `UPDATED:` and share a URL are stored once.

Rows are written to `$CYBERAU_DATA_DIR/ncsc_alerts.sqlite` until the shared intel store exists. A row is kept after it leaves the first page of the list.

## Operator guide

Read-only alerts from the public NCSC NZ alerts list. The site does not publish an RSS feed, so this connector reads the HTML list and one alert page.

| Tool | What it returns |
|---|---|
| `ncscnz_list_alerts` | Recent alerts with title, date and link, newest first in Australia/Sydney |
| `ncscnz_get_alert` | A short passage from one alert, plus the date and any CVE ids |

Titles that start with `UPDATED:` and point at the same URL are kept once. Titles and passages are untrusted. The list is cached for one hour and an alert page for seven days. One list page is fetched per hour, and an alert page at most once every five seconds.

Licence not confirmed. Quote short passages only. This connector is not endorsed by the NCSC.
