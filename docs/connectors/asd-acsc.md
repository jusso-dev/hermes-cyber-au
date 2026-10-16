# ASD's ACSC alerts, advisories and publications

Read-only RSS items from cyber.gov.au, plus cleaned text for one item page.

| Tool | What it returns |
|---|---|
| `asd_list_items` | Items from one or more feeds, newest first in Australia/Sydney |
| `asd_get_item` | Cleaned text, headings, CVE ids, ATT&CK ids and links for one cyber.gov.au page |
| `asd_search` | Items kept from earlier polls, including ones that have left the rolling feed |
| `asd_feed_status` | Which rung last served each feed: direct, HTTP/1.1 retry, snapshot, manual import, or stale |

Feeds are `alerts`, `advisories`, `publications`, `threats` and `news`. Titles and page text are untrusted. A failed live fetch retries once with an HTTP/1.1 browser-like header set that still names this project, then serves the last stored poll or the shipped snapshot. It does not present an empty list as a successful "no alerts" answer.

If cyber.gov.au cannot be reached, download the RSS in a browser and run `cyberau-mcp import asd <file> --feed alerts`.

Commonwealth of Australia material from ASD's ACSC (cyber.gov.au). Confirm the current licence at https://www.cyber.gov.au/about-us/copyright. This connector is not endorsed by ASD.
