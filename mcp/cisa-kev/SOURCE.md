# cisa-kev

- Upstream: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Auth: none
- Rate limit: one full download per 6 hours, with a conditional GET
- Terms: Creative Commons Zero 1.0. Cite CISA and the dateAdded field. Do not use the CISA logo or the DHS seal. See [Data sources, licences and attribution](../../docs/reference/data-sources.md).
- Verified: 2026-10-16
- Egress hosts: www.cisa.gov

## Fallback and fixtures

The catalogue is fetched live and cached for 6 hours. If the live fetch fails, or `CYBERAU_OFFLINE=1` is set, the connector's own cache answers when it has a copy. When there is no cached copy, every tool returns empty data with a warning that the CISA KEV catalogue is unavailable. No catalogue is shipped with the connector, so nothing from the repo is ever served as KEV data.

`CYBERAU_KEV_SNAPSHOT` may point at an operator-supplied catalogue file. It is read instead of the live feed, and every answer carries a warning that it came from that file, not a live fetch. The sample catalogue used by the tests lives in `tests/fixtures/kev.json` and is not real KEV data.
