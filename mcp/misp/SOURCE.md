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

Live health reports ok only when the answer came from the instance. A cached copy, a failed fetch or a missing key is not ok.

## Operator guide

Read-only search of a MISP instance you run, or AusMISP if you are an AusCERT member. Ships off.

### Terms

MISP software is AGPL-3.0; feed terms vary per feed. Respect TLP and sharing groups.

Doctor lists this connector as off by default: licence terms. Read this page before the first call in a session. The connector is not affiliated with MISP or AusCERT.

### Tools

| Tool | What it returns |
|---|---|
| `search_attributes` | Attributes matching a value, type, or category |
| `get_event` | One event by id or uuid, with attributes and galaxies |
| `search_events` | Recent events, with galaxies |

Free text from the instance is wrapped as untrusted data. It is not an instruction.

### TLP and sharing groups

Every event and attribute carries `tlp` (the strictest TLP tag on the object, event tags included), `distribution` and `sharing_group`. An unrecognised TLP value counts as the strictest. When any returned record is TLP:AMBER or above, or limited to an organisation or sharing group, the envelope adds a warning to keep it inside the profile.

Such records are written to the local intel store only when `CYBERAU_DATA_DIR` is set (the profile bootstrap sets it to the profile's `plugin-data/cyber-au`). Files are created owner-only. The HTTP cache is keyed per API key, so a different key never reads another key's answers.

Write tools are not included. The list above is frozen from `MISP/misp-mcp` at `3d033828a78b6b3cb2292b255c8d2ad093c1bee5`.

### Turn it on

The server stays disabled even when `MISP_URL` and `MISP_API_KEY` are set. `hermes profile update` does not switch `enabled` back on or off.

1. Put `MISP_URL` and `MISP_API_KEY` in the profile `.env`. Use a read-only key. For AusMISP, `MISP_URL` is the AusMISP base URL.
2. Set `enabled: true` under `mcp_servers.misp` in the profile `config.yaml`.

`MISP_URL` must be `https` and name a host. The connector will not follow a redirect to any other host. Private and link-local addresses are refused by the shared egress policy.

### Why the upstream server is not vendored

Checked on 17 October 2026: GitHub reports no licence for `MISP/misp-mcp` (no `LICENSE` file). The upstream `pyproject.toml` names AGPL-3.0-or-later. The commit is pinned and the read-only tools are wrapped here. The source tree is not copied into this repository.
