# CrowdStrike Falcon Adversary Intelligence Recon

Read-only notifications and monitoring rules from Falcon Adversary
Intelligence Recon. Creating or changing rules is out of scope. Rules are
managed in Falcon. Calls go through the official FalconPy SDK
(`query_notifications`, `get_notifications`, `query_rules`, `get_rules`).

Off by default: licence terms. A fresh install renders `enabled: false`
for `csrecon` even when the licence variables are set. Set `enabled: true`
in the profile `config.yaml` to turn it on. `hermes profile update` keeps
that choice.

Premium doctor reports `csrecon: off (paid, bring your own licence)` until
then. This page is the terms link. A skill that calls this connector states
these terms before the first call in a session.

## Tools

| Tool | What it returns |
| --- | --- |
| `cs_recon_notifications` | Notifications since a date: rule name, topic, summary |
| `cs_recon_rules` | Monitoring rules and their topics |

Rule names, filters and match summaries are untrusted text.

## Terms

| Flag | Default |
| --- | --- |
| `cache` | `session` |
| `cache_ttl_max_s` | `0` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

Commercial licence. Session cache. Store metadata only. No STIX export. Read scope only.

## Licence environment

Names only. Put values in the profile `.env`. Do not commit them.

- `FALCON_CLIENT_ID` (required)
- `FALCON_CLIENT_SECRET` (required)
- `FALCON_BASE_URL` (optional)

`FALCON_BASE_URL` defaults to `https://api.crowdstrike.com`. The API client
needs the Recon monitoring rules read scope only.

CrowdStrike Falcon is a commercial product. This connector is not endorsed
by CrowdStrike.
