# misp

- Upstream: https://github.com/MISP/misp-mcp
- Pinned commit: `3d033828a78b6b3cb2292b255c8d2ad093c1bee5` (launcher `misp-mcp`)
- Auth: `MISP_URL` and `MISP_API_KEY` from the profile `.env`, sent as the `Authorization` header. A read-only key is enough. Never logged.
- Rate limit: 30 requests per rolling minute, keyed by the server name `misp`.
- Terms: MISP software is AGPL-3.0; feed terms vary per feed. Respect TLP and sharing groups.
- Verified: 16 October 2026. Licence rechecked 17 October 2026.
- Egress hosts: user supplied. The host is taken from `MISP_URL` at request time. Any other host, including a redirect, is refused.

The upstream tree is not vendored. GitHub reports no licence for `MISP/misp-mcp` at that commit (there is no `LICENSE` file). `pyproject.toml` names AGPL-3.0-or-later, which is not a file we can rely on, and AGPL code does not belong in this Apache-2.0 repository. This package keeps the pinned read-only tool list and calls the instance REST API.

Included tools, frozen from that commit: `search_attributes`, `get_event`, `search_events`. Write tools are excluded. AusCERT members point `MISP_URL` at AusMISP.
