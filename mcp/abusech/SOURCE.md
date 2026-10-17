# abusech

- Upstream: https://abuse.ch/ (URLhaus https://urlhaus-api.abuse.ch/v1/, ThreatFox https://threatfox-api.abuse.ch/api/v1/, MalwareBazaar https://mb-api.abuse.ch/api/v1/, Feodo Tracker https://feodotracker.abuse.ch/downloads/ipblocklist.json)
- Auth: `Auth-Key` HTTP header from `ABUSECH_AUTH_KEY` (free key from https://auth.abuse.ch/, mandatory since 30 June 2025) for URLhaus, ThreatFox and MalwareBazaar. Feodo Tracker needs no key. The value is never logged, cached or returned, and is dropped on redirects.
- Rate limit: fair use with no published number. Self-imposed ceiling of 1 request a second per platform, 3 retries honouring `Retry-After`, 30 second timeout. Lookups cache for 1 hour, recent lists for 15 minutes, the Feodo blocklist for 1 hour.
- Terms: abuse.ch terms (effective 4 November 2025): free for not-for-profit use within query volume limits. Commercial users may need a paid subscription through Spamhaus. No high-volume automated harvesting. Feodo Tracker separately states its datasets are CC0. The connector ships off by default (`enabled: false`) and shows both statements in every envelope `attribution`. The operator decides whether their use is allowed.
- Verified: 2026-10-16
- Egress hosts: urlhaus-api.abuse.ch, threatfox-api.abuse.ch, mb-api.abuse.ch, feodotracker.abuse.ch

## What is called

| Tool | Calls |
|---|---|
| `abusech_lookup` | URLhaus `POST /v1/url/`, `/v1/host/` or `/v1/payload/`; ThreatFox `search_ioc` or `search_hash`; MalwareBazaar `get_info` |
| `threatfox_recent` | ThreatFox `get_iocs` (days 1 to 7). The `malware` filter is applied to the answer. |
| `feodo_blocklist` | Feodo Tracker `GET /downloads/ipblocklist.json`. The `country` filter is applied to the answer. |

URLhaus and MalwareBazaar take form-encoded bodies, ThreatFox takes JSON. SHA-1 only goes to MalwareBazaar because URLhaus payload and ThreatFox hash search accept MD5 and SHA-256.

The live health probe makes one call per group: URLhaus `GET /v1/urls/recent/limit/1/`, ThreatFox `get_iocs`, MalwareBazaar `get_recent` and the Feodo blocklist. The `limit/1` path segment follows the URLhaus API page and was not exercised on 16 October 2026 because no key was available from the build box. ThreatFox `malwareinfo` and MalwareBazaar `get_taginfo` are not used by any tool.

## Metadata only

No sample is downloaded. The connector never calls MalwareBazaar `get_file` or any URLhaus download path, drops the `urlhaus_download` link that URLhaus returns, and writes no sample to disk. Hashes, names, tags and intelligence counters are the whole of what comes back.

## Untrusted text

Every free text field (URLs, domains, file names, tags, comments, reporters, malware aliases, references) is wrapped with `untrusted_text`. Hashes, IP addresses and short enumerated values pass through only when they match a strict shape, otherwise they are wrapped too.

## Verified on 16 October 2026

URLhaus and ThreatFox returned 401 without a key. The Feodo JSON returned 200. Response shapes for the keyed platforms follow the abuse.ch API pages and are stored as `schema/*.response.json`. Fixtures and the shipped `data/snapshot.json` are synthetic: documentation address ranges (RFC 5737), `.test` domains and made-up hashes. Offline answers from the snapshot say so in `warnings`.

## Local history

Until the shared intel store exists, each normalised record is kept in `$CYBERAU_DATA_DIR/abusech_intel.sqlite` (table `observations`: key, observed_at, digest, record). A new row is added only when a record changes, so rolling ThreatFox and Feodo feeds and score changes are kept.

## Operator guide

Read-only indicator lookups and feeds from URLhaus, ThreatFox, MalwareBazaar and Feodo Tracker. Metadata only: no malware sample is downloaded or written to disk.

| Tool | What it returns |
|---|---|
| `abusech_lookup` | Records for a URL, domain, IP, MD5, SHA-1 or SHA-256 across URLhaus, ThreatFox and MalwareBazaar, with a status per platform |
| `threatfox_recent` | ThreatFox IOCs from the last 1 to 7 days, optionally filtered by malware family |
| `feodo_blocklist` | The current Feodo Tracker botnet C2 blocklist, optionally filtered by country code |

Free text (URLs, file names, tags, comments, reporters) is untrusted. Every envelope carries the attribution and terms below.

### Terms

This connector is off by default (`enabled: false`) because of the abuse.ch terms, effective 4 November 2025:

- Free for not-for-profit use within query volume limits.
- Commercial users may need a paid subscription through Spamhaus.
- No high-volume automated harvesting.
- Feodo Tracker datasets are separately stated to be CC0.

This project does not decide whether your use is covered. Read https://abuse.ch/ and decide before you turn it on. Indicators you look up are sent to abuse.ch.

### Turn it on

1. Get a free Auth-Key at https://auth.abuse.ch/ and add it to the profile `.env` as `ABUSECH_AUTH_KEY`. The key is read through the `${ABUSECH_AUTH_KEY}` placeholder and is never written to `config.yaml`.
2. Set `enabled: true` under `mcp_servers.abusech` in the profile `config.yaml`. That file is yours: bootstrap and `hermes profile update` keep your value, so an update never switches the connector on or off.

Having the key set does not enable the connector. `doctor` lists it as "off by default: licence terms" and points here. Without a key, only the Feodo blocklist works and the other tools return a warning that names `ABUSECH_AUTH_KEY`.

Attribution: data from abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker).
