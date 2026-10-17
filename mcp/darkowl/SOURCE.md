# darkowl

- Upstream: https://api.darkowl.com/api/v1/search
- Auth: HMAC-SHA1 of the method, the decoded path and query, and a UTC `Date` header. Sent as `Authorization: OWL <public key>:<base64 signature>`. The private key is only used to sign and is never logged.
- Rate limit: per licence. Local ceiling is 1 request a second, burst 2. Back off on 429 and honour `Retry-After`.
- Terms: Commercial licence. Session cache. Store counts and links only, no snippets. No STIX export. Off by default: licence terms.
- Verified: 2026-10-17
- Egress hosts: api.darkowl.com
