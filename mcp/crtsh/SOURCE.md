# crtsh

- Upstream: https://crt.sh/
- Auth: none
- Rate limit: one request every 5 seconds. Timeout 90 seconds.
- Terms: Public certificate transparency data from crt.sh.
- Verified: 2026-10-17
- Egress hosts: crt.sh

## Operator guide

Read-only certificate transparency records from [crt.sh](https://crt.sh/).

| Tool | What it returns |
|---|---|
| `crtsh_certs` | Certificates for a domain, deduplicated by serial number |

No API key. One request every 5 seconds, with a 90 second timeout, cached for 24 hours. Subdomain search uses a `%.` prefix. Expired certificates are left out unless `include_expired` is set. Names and issuer text are untrusted.

Fallback ladder: live crt.sh, then the connector's own cache of earlier answers, then unavailable. When crt.sh fails and no cached answer matches, the tool returns an empty list with a warning that the source is unavailable. No snapshot ships with the connector. An operator can point `CYBERAU_CRTSH_SNAPSHOT` at a crt.sh JSON file to answer from it instead of the network; every answer from that file carries a warning that it came from the operator-supplied snapshot file, not a live fetch. Test fixtures live under `tests/fixtures/` and are never served at runtime.

Public certificate transparency data from crt.sh.
