# hindsight

- Upstream: operator-supplied Hindsight server (retain and recall only). Product notes: https://hindsight.vectorize.io
- Auth: `Authorization: Bearer` from `HINDSIGHT_API_KEY` in the environment. No key is shipped. Requests omit the header when the variable is unset.
- Rate limit: one request per tool call, no client retries, 30 second timeout. No request is made until `HINDSIGHT_BASE_URL` is set.
- Terms: use only a Hindsight server you operate or are allowed to use. Recall text is wrapped as untrusted data unless the bank is `org` and the record is marked confirmed. Reflect is not implemented.
- Verified: 2026-10-17
- Egress hosts: none shipped. The client talks only to the origin of `HINDSIGHT_BASE_URL`, and it does not follow redirects.
