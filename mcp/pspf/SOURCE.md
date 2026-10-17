# pspf

- Upstream: https://www.protectivesecurity.gov.au/publications-library/pspf-page-2026 and https://www.protectivesecurity.gov.au/
- Auth: none
- Rate limit: regeneration only, at most two inventory refreshes a week. Each refresh may fetch the two pages, with one HTTP/1.1 retry if the first attempt fails. Timeout 60 seconds, 3 retries. User tools read the shipped snapshot and the local store.
- Terms: Licence not confirmed. Quote short passages with attribution. This connector is not a PSPF assessment and is not endorsed by the Australian Government.
- Verified: 2026-10-17
- Egress hosts: www.protectivesecurity.gov.au

## Runtime fetch on 17 October 2026

HTTP/2 to the home page failed before any body (curl exit 92, INTERNAL_ERROR). An HTTP/1.1 HEAD returned 200. An HTTP/1.1 GET then timed out with 0 bytes. The same class of failure was noted on 16 October 2026. The connector uses the same ladder as the ASD connector: direct fetch, then HTTP/1.1 with browser-like headers that still include `hermes-cyber-au`, then the last stored poll, then the shipped snapshot.

The snapshot quotes the publications-library description of PSPF on a page 2026 (1 July 2026) and the public descriptions of Direction 001-2026 (26 February 2026) and Direction 002-2026 (29 September 2026). It does not contain the mandatory requirements spreadsheet. A miss means the record is not in this snapshot. It is not a finding that no requirement exists.

Records are stored in `$CYBERAU_DATA_DIR/pspf.sqlite` until the shared intel store exists. Rows are not deleted when they leave a later page.
