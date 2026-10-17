# pspf

- Upstream: https://www.protectivesecurity.gov.au/publications-library/pspf-page-2026 and https://www.protectivesecurity.gov.au/protective-security-directions-under-pspf
- Auth: none
- Rate limit: at most two inventory refreshes a week, counted only when a page is not already in the HTTP cache (cache time to live one week). A refresh fetches the two pages with a 10 second timeout and one retry on each of two attempts, so a hung site cannot outlast the 120 second tool timeout. When the budget is spent the tools serve the last stored poll, then the shipped snapshot. `health --live` has its own budget.
- Terms: Licence not confirmed. Quote short passages with attribution. This connector is not a PSPF assessment and is not endorsed by the Australian Government.
- Verified: 2026-10-17
- Egress hosts: www.protectivesecurity.gov.au

## Runtime fetch on 17 October 2026

HTTP/2 to the home page failed before any body (curl exit 92, INTERNAL_ERROR). The shared client speaks HTTP/1.1 only. An HTTP/1.1 GET that carried the project user agent, which includes a `(+https://...)` URL, hung until the read timeout with 0 bytes. The same request with the user agent `hermes-cyber-au/0.1.0 (compatible; HTTP/1.1 fallback)` returned 200 in about 0.2 seconds for both pages. The connector uses the same ladder as the ASD connector: direct fetch, then HTTP/1.1 with that URL-free user agent and browser-like headers, then the last stored poll, then the shipped snapshot. Once the direct attempt has failed, later pages in the same refresh go straight to the HTTP/1.1 attempt.

The home page lists no directions. They are on the protective security directions page, which the connector fetches instead.

The snapshot quotes the publications-library description of PSPF on a page 2026 (1 July 2026) and the public descriptions of Direction 001-2026 (26 February 2026) and Direction 002-2026 (29 September 2026). It does not contain the mandatory requirements spreadsheet. A miss means the record is not in this snapshot. It is not a finding that no requirement exists.

Records are stored in `$CYBERAU_DATA_DIR/pspf.sqlite` until the shared intel store exists. Rows are not deleted when they leave a later page. Each row records whether it came from a live fetch (`live`) or the shipped snapshot (`snapshot`). Only live rows are served as the last stored poll, so the shipped snapshot is never reported as a stored poll, and a snapshot row never overwrites a live row.

Every record returned carries `url` (source URL), `retrieved_at` (when the page was fetched, or the snapshot date for the shipped snapshot), `origin`, and `source_sha256` (SHA-256 of the quotation text held in the record).
