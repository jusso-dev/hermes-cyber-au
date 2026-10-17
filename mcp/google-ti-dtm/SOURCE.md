# google-ti-dtm

- Upstream: https://gtidocs.virustotal.com/
- Auth: `GTI_API_KEY` as the `x-apikey` header, plus `x-tool: jusso-dev.hermes-cyber-au.0.1`. Never log the key. Do not reuse a VirusTotal Public API key.
- Rate limit: Per licence. This client stays at 1 request per second, burst 5, and backs off on HTTP 429 using Retry-After.
- Terms: Commercial licence. Session cache. Store metadata only. No STIX export. Redistribution forbidden. See docs/connectors/google-ti-dtm.md.
- Verified: 2026-10-16
- Egress hosts: www.virustotal.com

## Operator guide

Read-only alerts and monitors from Google Threat Intelligence Digital Threat Monitoring (formerly Mandiant). The feed is served at `www.virustotal.com/api/v3/dtm/`. It shares that host with VirusTotal and uses a different key. Do not reuse a VirusTotal Public API key.

The `gtidtm` server ships disabled. A fresh install stays off even when `GTI_API_KEY` is set. Turn it on with `enabled: true` under `mcp_servers.gtidtm` in your profile `config.yaml`. `hermes profile update` keeps that choice.

Doctor reports `gtidtm: off (paid, bring your own licence)` until you enable it. That is off by default because of the licence terms below.

### Terms

Commercial licence. Not legal advice. Defaults from `mcp/premium/vendors.yaml`:

| Flag | Default |
| --- | --- |
| `cache` | `session` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

Attribution on every result: Commercial licence. Session cache. Store metadata only. No STIX export. Do not reuse a VirusTotal Public API key.

Before the first call in a session, state these terms. The short version lives in `skills/google-ti-dtm/SKILL.md`.

### Tools

| Tool | What it returns |
| --- | --- |
| `gti_dtm_alerts` | DTM alerts since a date, with monitor, severity, alert type and matched value |
| `gti_dtm_monitors` | Configured monitors and what each watches |

`since` is a `YYYY-MM-DD` date in Australia/Sydney. Free text from the feed is wrapped as untrusted data. Nothing in this connector creates monitors, updates alerts, or downloads samples.

### Access

Set `GTI_API_KEY` in the profile `.env`. The process sends it as `x-apikey` and names this integration with `x-tool`. Nothing in this repository contains a licence key.

Requests stay at 1 per second with a burst of 5, and back off when the vendor returns HTTP 429 with `Retry-After`. Responses are kept for the session only. Metadata for watchlist matches is stored. Raw matched text is not.

Egress is limited to `www.virustotal.com`. A redirect or `Link` header that points elsewhere is refused before any request is sent, and the key is dropped on any redirect.

Offline mode and pinned snapshots answer with `cache: snapshot` and a warning that the data is not live. The copy shipped in the package is synthetic. Findings from a snapshot are never stored and never feed org exposure. `health --live` fails when the key is missing or the live fetch fails, and never counts a cached or snapshot copy as ok.

Checked on 16 October 2026 against the DTM list-alerts OpenAPI reference, the DTM pagination guide, and the `x-tool` header format in VirusTotal/gti-dev-kit.

Upstream reference: https://gtidocs.virustotal.com/
