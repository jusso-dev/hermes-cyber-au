# hibp

- Upstream: https://haveibeenpwned.com/mcp (official HIBP MCP server, https://haveibeenpwned.com/Docs/MCP). API reference: https://haveibeenpwned.com/API/v3
- Auth: none for breach metadata and the Pwned Passwords k-anonymity range. Account and domain lookups need an HIBP OAuth bearer token (scope `hibp.mcp`, active subscription) in `HIBP_API_KEY`, sent as `Authorization: Bearer`. Never logged, never cached, never in an envelope.
- Rate limit: public tools 1 request per second (burst 5). Keyed tools 10 per minute (burst 1), the lowest HIBP plan. A 429 `Retry-After` is honoured, capped at 60 seconds.
- Terms: breach data is CC BY 4.0 with attribution to Have I Been Pwned. No attribution requirement on Pwned Passwords. Do not misrepresent the data source.
- Verified: 2026-10-17
- Egress hosts: haveibeenpwned.com, api.pwnedpasswords.com

## Pinned wrap

This package wraps the official server. It does not reimplement HIBP endpoints. Each tool is one `tools/call` to `https://haveibeenpwned.com/mcp`, filtered to the five tools in `expected_tools.txt`, and the reply is re-wrapped in the shared envelope.

The server reported 17 tools on 2026-10-17 (`serverInfo.name` `hibp-mcp-server`, version `0.0.0`). Frozen: `hibp_list_breaches`, `hibp_get_breach`, `hibp_get_pwned_passwords_range`, `hibp_get_breached_account`, `hibp_get_breached_domain`.

Excluded on purpose:

- `hibp_get_latest_breach`, `hibp_list_data_classes`: harmless, but outside the ticket's tool list.
- `hibp_get_breached_account_range`, `hibp_get_paste_account`, `hibp_get_stealer_logs_by_email`, `hibp_get_stealer_logs_by_website_domain`, `hibp_get_stealer_logs_by_email_domain`, `hibp_list_subscribed_domains`, `hibp_get_subscription_status`: personal or account data, out of scope for v0.1.
- `hibp_generate_domain_verification_dns_token`, `hibp_verify_domain_verification_dns_token`, `hibp_send_domain_verification_email`: write tools (`readOnlyHint` false). This connector is read-only.

A tool that appears upstream and is not in the list is ignored. A listed tool that disappears fails `cyberau-mcp health hibp --live`.

## Privacy

- Passwords are never sent. The range tool accepts only a 5 character hex prefix and rejects anything else without echoing it. Hash locally with SHA-1 and pass the first five characters.
- `hibp_get_breached_account` and `hibp_get_breached_domain` need an approval token bound to the tool and the subject. Without one the call is blocked before any request is made, and the block is logged. The token is `HMAC-SHA256(CYBERAU_APPROVAL_KEY, "<tool>:<sha256 of the lowercased subject>")`, issued by the `cyber-au` plugin `pre_tool_call` guard after a human approves. With no `CYBERAU_APPROVAL_KEY` set, every gated call is blocked.
- Gated results are never cached on disk, never written to the intel store, and never contain the email address or domain that was searched. The audit log holds a truncated SHA-256 of the subject only.

## Fixtures

- `breaches.json`, `range_21BD1.txt` and the three public cassettes were recorded from the live service on 2026-10-17. Breach data is CC BY 4.0, Have I Been Pwned.
- `account-exists`, `multiple-breaches`, `hibp_401.json` and the two keyed cassettes were built by hand to the server's published output schema. No subscription key was available at build time. They name only HIBP's published test accounts on hibp-integration-tests.com. Re-record them with a key when one is available.

## Operator guide

A pinned, read-only wrap of the official HIBP MCP server (`https://haveibeenpwned.com/mcp`), filtered to five tools. Every reply comes back in the shared envelope with the HIBP attribution string.

| Tool | What it returns | Needs |
|---|---|---|
| `hibp_list_breaches` | Public breach metadata, optionally for one domain | nothing |
| `hibp_get_breach` | One breach by its HIBP name, for example `Adobe` | nothing |
| `hibp_get_pwned_passwords_range` | Pwned Passwords suffixes and counts for a 5 character SHA-1 prefix | nothing |
| `hibp_get_breached_account` | Breach names for one email address | `HIBP_API_KEY` and human approval |
| `hibp_get_breached_domain` | Breached aliases on one verified domain | `HIBP_API_KEY` and human approval |

Breach titles and descriptions, and domain aliases, are untrusted text. The breach list is cached for 24 hours. With `CYBERAU_OFFLINE=1` the connector answers from the cache or a small shipped snapshot and says so in `warnings`.

### Passwords

Passwords never leave the machine. Hash locally with SHA-1 and pass the first five hex characters only. The tool rejects anything else, without repeating it back.

### Account and domain lookups

These touch personal information.

- The call is blocked unless the `cyber-au` guard supplies an approval token for that exact tool and subject. Every decision is logged as a truncated hash, never the address.
- `HIBP_API_KEY` holds an HIBP OAuth bearer token for the `hibp.mcp` scope on an account with a subscription. The official server does not document a v3 API key header, so a plain API key is not assumed to work.
- Results are never cached on disk, never written to the intel store, and do not repeat the address or domain that was searched.
- Without the key, only the public tools work.

Excluded on purpose: paste, stealer log, subscription and domain verification tools. See `mcp/hibp/SOURCE.md`.

Breach data from Have I Been Pwned (https://haveibeenpwned.com), licensed CC BY 4.0. Pwned Passwords range data from Have I Been Pwned. This connector is not endorsed by Have I Been Pwned.
