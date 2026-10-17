# Scamwatch alerts

Read-only alerts from the Scamwatch homepage.

| Tool | What it returns |
|---|---|
| `scamwatch_list_alerts` | Current alerts with title, date, link, and short summary |
| `scamwatch_get_alert` | One scamwatch.gov.au page as cleaned text |

No access key. The connector polls at most once every 6 hours. Titles, summaries, and page text are untrusted.

A 403 from www.scamwatch.gov.au is reported as blocked. It is not treated as an empty alert list. If an earlier copy is cached, that copy is returned with the blocked warning.

The connector does not submit scam reports or contact people. Statistics in the embedded Power BI report are out of scope.

Scamwatch alerts from scamwatch.gov.au (ACCC). Licence not confirmed. This connector is not endorsed by the ACCC or Scamwatch.
