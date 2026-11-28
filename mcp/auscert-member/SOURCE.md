# auscert-member

- Upstream: https://auscert.org.au/services/threat-intelligence/
- Auth: Paid AusCERT membership. `AUSCERT_URL_FEED` is the member feed URL from AusCERT. `AUSCERT_FEED_TOKEN`, when the feed needs one, is sent as `Authorization: Bearer <token>`. Both come from the profile `.env`. Never logged, never cached by value, never returned.
- Rate limit: Per member terms; default hourly. The feed is fetched at most once an hour (one hour cache), with a ceiling of 4 requests in any 4 minutes for retries and probes.
- Terms: AusCERT member data, used under your AusCERT membership terms. Keep it inside your organisation and do not republish it.
- Verified: 16 October 2026: membership and service pages read; feed format not public. Built on 28 November 2026 on the maintainer's instruction with the feed format assumed (below).
- Egress hosts: user supplied. The host is taken from `AUSCERT_URL_FEED` at request time. Any other host, including a redirect, is refused.

AusMISP is reached through the MISP connector (`mcp/misp`), not here.

## Turn it on

Doctor lists this connector as off by default: licence terms. Read the terms above before the first call in a session. The `auscertm` server stays disabled even when `AUSCERT_URL_FEED` is set, and `hermes profile update` never switches `enabled` on or off.

1. Put `AUSCERT_URL_FEED` (and `AUSCERT_FEED_TOKEN` if AusCERT gave you a credential) in the profile `.env`.
2. Set `enabled: true` under `mcp_servers.auscertm` in the profile `config.yaml`.
3. Run `cyberau-mcp health auscert-member --live` to check the feed answers and parses.

`AUSCERT_URL_FEED` must be an `https` URL that names a host, with no user name or password in it. The connector will not follow a redirect to any other host. Private and link-local addresses are refused by the shared egress policy.

## Feed format (assumed)

AusCERT does not publish the member URL feed format, and no member has confirmed it for this repository. The connector accepts the two shapes most malicious URL feeds use:

1. Plain text: one URL per line. Blank lines and lines starting with `#` are skipped, and text after ` #` on a line is a comment. Defanged `hxxp`, `hxxps`, `[.]` and `[:]` are refanged.
2. CSV with a header row naming a `url` column (`uri` and `link` are also read). Optional columns `first_seen` (or `date`, `date_added`, `added`) and `category` (or `type`, `threat`) are kept as untrusted text.

A text line that is not an http or https URL, or a CSV without a `url` column, is schema drift: the tools return a warning and `cyberau-mcp health auscert-member --schema-drift` fails. To adjust for a different format, change `parse_feed` in `src/cyberau_auscert_member/source.py`, add a fixture with the new shape (synthetic values only, never member data), and update the tests and this section.

## Behaviour

- `auscert_url_feed_lookup` checks one URL (exact match after normalising scheme, host case, default port and a trailing slash) or one domain (the domain and its subdomains) against the cached feed. It never requests the URL under test.
- `auscert_url_feed_status` reports whether the feed is configured, the entry count, when the cached copy was fetched, the cache state and the format detected.
- Fallback ladder: live feed, then the local HTTP cache (fresh, or stale when the fetch fails, times out or returns 429 or a 5xx), then unavailable. There is no shipped snapshot. `CYBERAU_AUSCERT_MEMBER_SNAPSHOT` may point at an operator-supplied feed file; answers from it say so.
- Matched entries are kept in `auscert-member.sqlite` (owner only) under the profile data directory, only when `CYBERAU_DATA_DIR` is set. Member data never enters this repository or its fixtures.
- Live health reports ok only when the answer came from the feed itself. It cannot be run in CI without a membership.
