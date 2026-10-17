# nvd

- Upstream: https://nvd.nist.gov/developers/vulnerabilities
- Auth: optional `NVD_API_KEY` sent as the `apiKey` header. Never logged.
- Rate limit: 5 requests per rolling 30 seconds without a key, 50 with a key.
- Terms: This product uses data from the NVD API but is not endorsed or certified by the NVD. See [Data sources, licences and attribution](../../docs/reference/data-sources.md).
- Verified: 2026-10-16
- Egress hosts: services.nvd.nist.gov
