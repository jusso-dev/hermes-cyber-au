# irap

- Upstream: https://www.cyber.gov.au/irap and https://www.cyber.gov.au/business-government/protecting-devices-systems/assessment-evaluation-programs/irap/irap-consumer-guide
- Auth: none
- Rate limit: regeneration only, weekly, one request every 6 seconds (under the one-request-per-5-seconds ceiling). One retry, then an HTTP/1.1 fallback. Timeout 60 seconds.
- Terms: Commonwealth of Australia material. The July 2025 consumer guide states that, except for the Coat of Arms, its material is under a Creative Commons Attribution 4.0 International licence. Quote short passages with attribution. This connector is not an IRAP assessment and is not endorsed by ASD. Confirm https://www.cyber.gov.au/about-us/copyright before reuse.
- Verified: 2026-10-16
- Egress hosts: www.cyber.gov.au

## Runtime fetch

Direct fetches of cyber.gov.au failed on 16 October 2026, as recorded in the connector research, and again from this environment on 17 October 2026. The shipped snapshot quotes short passages seen through a search index of the IRAP overview and the July 2025 consumer guide, including the Appendix B preparation checklist. A live health check from a network that can reach cyber.gov.au is still required before treating the pages as current.

The fallback ladder is a direct fetch, then HTTP/1.1 with browser-like headers that still include `hermes-cyber-au` in the User-Agent, then the last stored copy, then the shipped snapshot. After a connection failure, later pages in the same call use the snapshot.

The live health probe fetches both pages and fails if either cannot be fetched from cyber.gov.au. It never counts the shipped snapshot or a cached copy as ok.

A question the pages do not answer is returned as `not covered`. Queries made only of common words (for example "should" or "what is this") are also `not covered`. The connector does not turn that into an assessment result.

Items are stored in `$CYBERAU_DATA_DIR/irap_guidance.sqlite` (table `guidance`) until the shared intel store exists. Rows are kept when a later copy of the page no longer includes them. Search answers from the current page or snapshot, not from dropped rows.
