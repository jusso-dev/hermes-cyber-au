# nvd

- Upstream: https://nvd.nist.gov/developers/vulnerabilities
- Auth: optional `NVD_API_KEY` sent as the `apiKey` header. Never logged.
- Rate limit: 5 requests per rolling 30 seconds without a key, 50 with a key.
- Terms: This product uses data from the NVD API but is not endorsed or certified by the NVD. See [Data sources, licences and attribution](../../docs/reference/data-sources.md).
- Verified: 2026-10-16
- Egress hosts: services.nvd.nist.gov

## Fallback and fixtures

Each call is fetched live and cached (24 hours for a CVE or its history, 1 hour for a search). If the live fetch fails, or `CYBERAU_OFFLINE=1` is set, the connector's own cache answers when it has a copy of that request. When there is no cached copy, the tool returns empty data with a warning that NVD is unavailable. No CVE data is shipped with the connector, so nothing from the repo is ever served as NVD data.

`CYBERAU_NVD_SNAPSHOT` may point at an operator-supplied NVD response file. It is read instead of the live API, and every answer carries a warning that it came from that file, not a live fetch. The sample responses used by the tests live in `tests/fixtures/` and are not real NVD records.
