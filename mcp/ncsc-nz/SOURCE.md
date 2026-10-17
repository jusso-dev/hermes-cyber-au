# ncsc-nz

- Upstream: https://www.ncsc.govt.nz/alerts/ HTML list (`?start=N`, 12 alerts a page). No RSS. cert.govt.nz redirects here.
- Auth: none
- Rate limit: one list page per hour. Alert pages at most one request every 5 seconds.
- Terms: Licence not confirmed. Return title, date, link and extracted CVEs. Quote short passages only. This connector is not endorsed by the NCSC.
- Verified: 2026-10-16 the alerts page returned 200 from the build box. On 2026-10-17 live health returned ok from this host over HTTP/1.1 and the first page parsed to 12 alerts. An HTTP/2 GET from this host received a bot-check 403.
- Egress hosts: www.ncsc.govt.nz

The list selectors the schema check requires are `explore--alert` or `card--alert`, and on each card `card__link`, `card__title` and `card__date`. Alerts whose titles start with `UPDATED:` and share a URL are stored once.

Rows are written to `$CYBERAU_DATA_DIR/ncsc_alerts.sqlite` until the shared intel store exists. A row is kept after it leaves the first page of the list.
