# NCSC NZ alerts (formerly CERT NZ)

Read-only alerts from the public NCSC NZ alerts list. The site does not publish an RSS feed, so this connector reads the HTML list and one alert page.

| Tool | What it returns |
|---|---|
| `ncscnz_list_alerts` | Recent alerts with title, date and link, newest first in Australia/Sydney |
| `ncscnz_get_alert` | A short passage from one alert, plus the date and any CVE ids |

Titles that start with `UPDATED:` and point at the same URL are kept once. Titles and passages are untrusted. The list is cached for one hour and an alert page for seven days. One list page is fetched per hour, and an alert page at most once every five seconds.

Licence not confirmed. Quote short passages only. This connector is not endorsed by the NCSC.
