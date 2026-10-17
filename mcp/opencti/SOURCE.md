# opencti

- Upstream: https://docs.opencti.io/
- Auth: `OPENCTI_URL` and `OPENCTI_TOKEN` for a read-only user. The token is sent as a bearer header and is never logged.
- Rate limit: 2 requests per second, burst 10, per instance host. This is a client ceiling. Stay under the limit set on the instance.
- Terms: OpenCTI Community Edition is Apache-2.0. Enterprise Edition has its own licence. Data in your instance stays under the terms you agreed with its sources. This connector is not endorsed by Filigran.
- Verified: 2026-10-16
- Egress hosts: user supplied. The connector allows only the host of `OPENCTI_URL`, plus any host listed here. Redirects to any other host are refused.

The static allowlist ships with no hosts because the instance is yours. Private, link-local and carrier-grade NAT addresses stay blocked.
