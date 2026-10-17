# Have I Been Pwned

A pinned, read-only wrap of the official HIBP MCP server (`https://haveibeenpwned.com/mcp`), filtered to five tools. Every reply comes back in the shared envelope with the HIBP attribution string.

| Tool | What it returns | Needs |
|---|---|---|
| `hibp_list_breaches` | Public breach metadata, optionally for one domain | nothing |
| `hibp_get_breach` | One breach by its HIBP name, for example `Adobe` | nothing |
| `hibp_get_pwned_passwords_range` | Pwned Passwords suffixes and counts for a 5 character SHA-1 prefix | nothing |
| `hibp_get_breached_account` | Breach names for one email address | `HIBP_API_KEY` and human approval |
| `hibp_get_breached_domain` | Breached aliases on one verified domain | `HIBP_API_KEY` and human approval |

Breach titles and descriptions, and domain aliases, are untrusted text. The breach list is cached for 24 hours. With `CYBERAU_OFFLINE=1` the connector answers from the cache or a small shipped snapshot and says so in `warnings`.

## Passwords

Passwords never leave the machine. Hash locally with SHA-1 and pass the first five hex characters only. The tool rejects anything else, without repeating it back.

## Account and domain lookups

These touch personal information.

- The call is blocked unless the `cyber-au` guard supplies an approval token for that exact tool and subject. Every decision is logged as a truncated hash, never the address.
- `HIBP_API_KEY` holds an HIBP OAuth bearer token for the `hibp.mcp` scope on an account with a subscription. The official server does not document a v3 API key header, so a plain API key is not assumed to work.
- Results are never cached on disk, never written to the intel store, and do not repeat the address or domain that was searched.
- Without the key, only the public tools work.

Excluded on purpose: paste, stealer log, subscription and domain verification tools. See `mcp/hibp/SOURCE.md`.

Breach data from Have I Been Pwned (https://haveibeenpwned.com), licensed CC BY 4.0. Pwned Passwords range data from Have I Been Pwned. This connector is not endorsed by Have I Been Pwned.
