# Flashpoint Ignite

Read-only indicator context from Flashpoint Ignite. This is a paid feed. It ships disabled until you set `enabled: true` for `mcp_servers.flashpoint` in your profile `config.yaml`. Put your own Ignite token in `FLASHPOINT_API_TOKEN`. An update does not change that switch.

| Tool | What it returns |
|---|---|
| `flashpoint_indicator` | Context for one indicator value: type, timestamps, score, and a short note |

`flashpoint_credential_exposure` is not included. On 17 October 2026 the docs portal at <https://docs.flashpoint.io/> redirected to an Ignite sign-in page, so the credential sightings search path could not be confirmed. It is not called.

## Terms

Commercial licence. Session cache. Store metadata only. No STIX export. No sharing outside the profile. Redistribution is forbidden.

| Flag | Default |
|---|---|
| `cache` | `session` |
| `store` | `metadata` |
| `stix_export` | `false` |
| `share_outside_profile` | `false` |
| `redistribution` | `forbidden` |

`doctor` reports this server as `off (paid, bring your own licence)` until you enable it. The full note is [docs/premium/terms/flashpoint.md](../premium/terms/flashpoint.md).

A skill that calls this connector states these terms before the first call in a session.

Indicator notes are untrusted text. The connector does not keep them in the history log. Flashpoint has not published a rate limit. This connector allows a burst of two calls, then one every two seconds, and backs off on 429.

Attribution: Commercial licence. Session cache. Store metadata only. No STIX export.
