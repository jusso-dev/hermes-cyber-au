# hindsight

- Upstream: operator-supplied Hindsight server (retain and recall only). Product notes: https://hindsight.vectorize.io
- Auth: `Authorization: Bearer` from `HINDSIGHT_API_KEY` in the environment. No key is shipped. Requests omit the header when the variable is unset.
- Rate limit: one request per tool call, no client retries, 30 second timeout. No request is made until `HINDSIGHT_BASE_URL` is set.
- Terms: use only a Hindsight server you operate or are allowed to use. Recall text is wrapped as untrusted data unless the bank is `org` and the record is marked confirmed. Reflect is not implemented.
- Verified: 2026-10-17
- Egress hosts: none shipped. The client talks only to the origin of `HINDSIGHT_BASE_URL`, which must be https. Before every request it resolves the host and refuses loopback, link-local, multicast, reserved, IPv4-mapped, and 6to4 addresses, then connects to the address it checked. RFC 1918 and Tailscale addresses are allowed, so a Hindsight server on the homelab LAN or tailnet can be used. It does not follow redirects, so the key is never sent to another host.
