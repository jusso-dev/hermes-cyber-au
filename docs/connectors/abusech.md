# abuse.ch

Read-only indicator lookups and feeds from URLhaus, ThreatFox, MalwareBazaar and Feodo Tracker. Metadata only: no malware sample is downloaded or written to disk.

| Tool | What it returns |
|---|---|
| `abusech_lookup` | Records for a URL, domain, IP, MD5, SHA-1 or SHA-256 across URLhaus, ThreatFox and MalwareBazaar, with a status per platform |
| `threatfox_recent` | ThreatFox IOCs from the last 1 to 7 days, optionally filtered by malware family |
| `feodo_blocklist` | The current Feodo Tracker botnet C2 blocklist, optionally filtered by country code |

Free text (URLs, file names, tags, comments, reporters) is untrusted. Every envelope carries the attribution and terms below.

## Terms

This connector is off by default (`enabled: false`) because of the abuse.ch terms, effective 4 November 2025:

- Free for not-for-profit use within query volume limits.
- Commercial users may need a paid subscription through Spamhaus.
- No high-volume automated harvesting.
- Feodo Tracker datasets are separately stated to be CC0.

This project does not decide whether your use is covered. Read https://abuse.ch/ and decide before you turn it on. Indicators you look up are sent to abuse.ch.

## Turn it on

1. Get a free Auth-Key at https://auth.abuse.ch/ and add it to the profile `.env` as `ABUSECH_AUTH_KEY`. The key is read through the `${ABUSECH_AUTH_KEY}` placeholder and is never written to `config.yaml`.
2. Set `enabled: true` under `mcp_servers.abusech` in the profile `config.yaml`. That file is yours: bootstrap and `hermes profile update` keep your value, so an update never switches the connector on or off.

Having the key set does not enable the connector. `doctor` lists it as "off by default: licence terms" and points here. Without a key, only the Feodo blocklist works and the other tools return a warning that names `ABUSECH_AUTH_KEY`.

Attribution: data from abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker).
