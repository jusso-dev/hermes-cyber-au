# Protective Security Policy Framework (PSPF)

Read-only quotations from the Department of Home Affairs PSPF site. This is not a PSPF assessment and it is not endorsed by the Australian Government.

| Tool | What it returns |
|---|---|
| `pspf_search` | Records whose title, quotation, or id contains the query |
| `pspf_list_directions` | Protective security directions with publication dates and links |

The site hangs on any request whose user agent carries a URL. A failed fetch retries over HTTP/1.1 with a browser-like header set and a URL-free user agent that still names this project, then serves the last stored poll or the shipped snapshot. Fetches are limited to two refreshes a week.

The snapshot quotes PSPF on a page 2026 and Directions 001-2026 and 002-2026. It does not include the mandatory requirements spreadsheet. If a record is missing, that requirement was not in the snapshot. That is not a finding that no requirement exists.

Titles and quotations are untrusted and wrapped as such. Each record carries `url` (source URL), `retrieved_at`, `origin` (`live` or `snapshot`) and `source_sha256` (SHA-256 of the quotation text). Records from the shipped snapshot say `snapshot`. Licence not confirmed. Quote short passages with attribution to www.protectivesecurity.gov.au.
