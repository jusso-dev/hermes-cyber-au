# first-epss

- Upstream: https://api.first.org/epss/
- Auth: none
- Rate limit: 1,000 requests a minute. Batch at most 100 CVEs per call.
- Terms: FIRST publishes EPSS scores freely and requests attribution in a publication or product. Cite the model version and the score date. See [Data sources, licences and attribution](../../docs/reference/data-sources.md).
- Verified: 2026-10-16
- Egress hosts: api.first.org, www.first.org, epss.empiricalsecurity.com

## Fallback and fixtures

Each call is fetched live and cached for 12 hours. If the live fetch fails, or `CYBERAU_OFFLINE=1` is set, the connector's own cache answers when it has a copy of that request. When there is no cached copy, the tool returns empty data with a warning that FIRST EPSS is unavailable. No scores are shipped with the connector, so nothing from the repo is ever served as EPSS data.

`CYBERAU_EPSS_SNAPSHOT` may point at an operator-supplied EPSS response file. It is read instead of the live API, and every answer carries a warning that it came from that file, not a live fetch. The sample responses used by the tests live in `tests/fixtures/` and are not real EPSS scores.
