# osv

- Upstream: https://google.github.io/osv.dev/api/
- Auth: none
- Rate limit: no key. Self-imposed 10 requests a second. Use `osv_batch` for lists.
- Terms: OSV data is aggregated from many databases. Each record's `database_specific` source and licence fields are kept in every record.
- Verified: 2026-10-16
- Egress hosts: api.osv.dev

## Operator guide

Read-only open source vulnerability records from the OSV.dev API.

| Tool | What it returns |
|---|---|
| `osv_query` | Records affecting one package, optionally at one version |
| `osv_get` | One record by id (GHSA, PYSEC, GO and others) |
| `osv_batch` | Record ids and modified times for up to 100 package queries in one call |

No API key. The connector keeps itself under 10 requests a second, so use `osv_batch` for lists. Records are cached for 24 hours and query results for 6 hours. Summaries, details and every `database_specific` key and value are untrusted text. A record's `withdrawn` time is returned when OSV sets one, so skip withdrawn records.

OSV aggregates many databases. Each record keeps its `database_specific` source and licence fields, and `source` and `licence` are lifted to the top of the record when present. Cite the original database as well as OSV.

Attribution: OSV.dev.

### Fallback and fixtures

If the live fetch fails, or `CYBERAU_OFFLINE=1` is set, the connector's own cache answers when it has a copy of that request. When there is no cached copy, the tool returns empty data with a warning that OSV.dev is unavailable. No OSV records are shipped with the connector, so nothing from the repo is ever served as OSV data.

`CYBERAU_OSV_SNAPSHOT` may point at an operator-supplied OSV response file. It is read instead of the live API, and every answer carries a warning that it came from that file, not a live fetch. From that file, `osv_batch` is answered by package, not by position, and is not filtered by version. The sample responses used by the tests live in `tests/fixtures/`.
