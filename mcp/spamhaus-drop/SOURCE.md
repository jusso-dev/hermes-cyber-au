# spamhaus-drop

- Upstream: https://www.spamhaus.org/blocklists/do-not-route-or-peer/
- Auth: none
- Rate limit: cache each list for 24 hours, and never auto-fetch more than once an hour
- Terms: Provided free of charge; formal licence text not confirmed. Attribute Spamhaus.
- Verified: 2026-10-17
- Egress hosts: www.spamhaus.org

## Operator guide

Read-only checks against the Spamhaus Don't Route Or Peer lists: DROP (IPv4), DROPv6 and ASN-DROP.

| Tool | What it returns |
|---|---|
| `drop_check_ip` | Whether an IPv4 or IPv6 address is inside a DROP netblock, with the SBL id |
| `drop_check_asn` | Whether an autonomous system number is on ASN-DROP |
| `drop_list_status` | Last fetch time and entry counts for each list |

Public feeds, with no API key. The three lists are cached for 24 hours and refreshed at most once an hour. Registry names, AS names and domains come back as untrusted text. An SBL id or country code that does not match its expected shape is wrapped too, as is any upstream error text. Live health probes all three lists.

Fallback ladder: a fresh cached copy, then a live fetch, then the stale cached copy, then unavailable. No snapshot ships with the connector. When nothing live or cached can be read, each tool returns empty data with a warning that the DROP data is unavailable, and `drop_list_status` reports zero entries. Offline mode (`CYBERAU_OFFLINE=1`) reads only the cache.

An operator can point `CYBERAU_DROP_SNAPSHOT` at a directory holding `drop_v4.json`, `drop_v6.json` and `asndrop.json` in the upstream JSON lines format. Those files are then served instead of fetching, and every answer carries a warning that the data came from the operator-supplied snapshot, not a live fetch. The offline schema check reads that directory, or the cache when it is unset, and reports that there is no local copy to check when neither exists.

The synthetic test lists, built from RFC 5737 and RFC 3849 documentation ranges, live under `tests/fixtures/` and are never served at runtime.

Attribute Spamhaus. The lists are provided free of charge. Formal licence text was not confirmed.

Checked against the public JSON feeds on 17 October 2026.
