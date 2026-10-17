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

Public certificate transparency data from crt.sh.
