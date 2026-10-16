from common import *

E = "epic-intel-store"

SCHEMA_SQL = """\
-- plugins/cyber-au/store/migrations/0001_init.sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE schema_version (version INTEGER NOT NULL);

CREATE TABLE sources (
  id            TEXT PRIMARY KEY,            -- connector key, e.g. 'cisa-kev'
  name          TEXT NOT NULL,
  licence       TEXT,
  default_tlp   TEXT NOT NULL DEFAULT 'CLEAR'
);

CREATE TABLE indicators (
  id            TEXT PRIMARY KEY,            -- STIX SCO id, deterministic UUIDv5 (see export ticket)
  type          TEXT NOT NULL CHECK (type IN ('ipv4','ipv6','domain','url','email','md5','sha1','sha256','asn','cidr')),
  value         TEXT NOT NULL,               -- as first seen (kept for audit)
  value_norm    TEXT NOT NULL,               -- canonical form used for dedupe
  first_seen    TEXT NOT NULL,               -- ISO 8601 UTC
  last_seen     TEXT NOT NULL,
  verdict       TEXT CHECK (verdict IN ('malicious','suspicious','benign','unknown')),
  confidence    INTEGER CHECK (confidence BETWEEN 0 AND 100),
  tlp           TEXT NOT NULL DEFAULT 'CLEAR',
  UNIQUE (type, value_norm)
);

CREATE TABLE observations (
  id            INTEGER PRIMARY KEY,
  indicator_id  TEXT NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
  source_id     TEXT NOT NULL REFERENCES sources(id),
  source_ref    TEXT,                        -- upstream id or URL
  observed_at   TEXT NOT NULL,
  verdict       TEXT,
  confidence    INTEGER,
  tags          TEXT,                        -- JSON array
  raw_sha256    TEXT NOT NULL,               -- hash of the upstream record, never the record itself for keyed sources
  UNIQUE (indicator_id, source_id, source_ref, raw_sha256)
);

CREATE TABLE vulnerabilities (
  cve_id        TEXT PRIMARY KEY,
  kev_date_added TEXT, kev_due_date TEXT, kev_ransomware TEXT,
  epss          REAL, epss_percentile REAL, epss_date TEXT,
  cvss_v3       REAL, cvss_v4 REAL, cwe TEXT,
  updated_at    TEXT NOT NULL
);
CREATE TABLE epss_history (cve_id TEXT, date TEXT, epss REAL, percentile REAL, PRIMARY KEY (cve_id, date));

CREATE TABLE advisories (
  id            TEXT PRIMARY KEY,            -- e.g. 'asd:alerts:<sha1(link)>'
  source_id     TEXT NOT NULL REFERENCES sources(id),
  title         TEXT NOT NULL,
  url           TEXT NOT NULL,
  published_at  TEXT,
  summary       TEXT,                        -- untrusted text, stored wrapped
  content_sha256 TEXT,
  first_seen    TEXT NOT NULL
);
CREATE TABLE advisory_refs (advisory_id TEXT REFERENCES advisories(id), ref_type TEXT, ref TEXT, PRIMARY KEY (advisory_id, ref_type, ref));

CREATE TABLE relationships (
  src_id TEXT NOT NULL, rel TEXT NOT NULL, dst_id TEXT NOT NULL, source_id TEXT, first_seen TEXT,
  PRIMARY KEY (src_id, rel, dst_id)
);

CREATE TABLE routine_state (routine TEXT PRIMARY KEY, watermark TEXT, updated_at TEXT);

CREATE VIRTUAL TABLE fts USING fts5(kind, ref, title, body, tokenize = 'porter unicode61');
"""


def tickets():
    out = []
    out.append(dict(key="store-schema-ingest", parent=E, milestone=M_V01,
        labels=["type:feature", "area:intel-store", "priority:p0"],
        title="Local threat intel store: SQLite schema, ingest API and canonical dedupe",
        body=dedent(f"""
## Outcome
A local, single-file threat intel store that every connector, skill and routine writes to and reads from, with deterministic dedupe.

## Decision: SQLite first, DuckDB optional
SQLite (WAL, FTS5) because Hermes plugins already get a documented durable state location with a WAL SQLite option ({hsrc('website/docs/developer-guide/plugins/index.md')}, "Store durable state"), it needs no extra service, and multiple MCP processes can read it safely. DuckDB stays an optional analytics export in v1.0 (separate ticket).

Location: `<profile>/plugin-data/cyber-au/intel.sqlite`.

## Schema
```sql
{SCHEMA_SQL}```

## Canonicalisation (dedupe key = `(type, value_norm)`)
| Type | Rule |
|---|---|
| ipv4 | `ipaddress.ip_address()`; reject leading zeros |
| ipv6 | compressed lowercase form |
| domain | refang, strip trailing dot, lowercase, IDNA 2008 to punycode (`idna` package), reject invalid labels |
| url | refang, RFC 3986 normalisation: lowercase scheme and host, remove default port, resolve dot segments, keep query order, drop fragment |
| email | lowercase domain part only |
| hashes | lowercase hex, length checked |
| cidr | `ipaddress.ip_network(strict=False)` |
Refang rules: `hxxp`, `[.]`, `(.)`, `[:]`, `[at]`. Covered by property tests.

## Ingest API (`plugins/cyber-au/store/api.py`, also exposed as `cyberau-mcp store ...`)
```python
def upsert_indicator(type: str, value: str, *, source: str, observed_at: str, verdict=None,
                     confidence=None, tags=(), tlp="CLEAR", source_ref=None, raw: bytes) -> str  # returns id
def upsert_vulnerability(cve_id: str, **fields) -> None
def upsert_advisory(id: str, *, source: str, title: str, url: str, published_at, summary, content_sha256) -> bool  # True if new
def search(query: str, *, kinds=("indicator","advisory","vulnerability"), limit=20) -> list[dict]
```
Merge rule on conflict: `first_seen = min`, `last_seen = max`, verdict and confidence recomputed from observations with the formula in `docs/intel/scoring.md`, TLP takes the most restrictive value.

## Plugin tools
| Tool | Input |
|---|---|
| `intel_search` | {{"query": string, "kinds": array, "since": date, "limit": int<=100}} |
| `intel_get` | {{"id_or_value": string, "type": string?}} |
| `intel_add_observation` | {{"type", "value", "verdict"?, "confidence"?, "tags"?, "tlp"?, "note"?}}; records `source_id = 'analyst'` |

## Acceptance criteria
- [ ] Ingesting the same KEV catalogue twice leaves row counts unchanged.
- [ ] `hxxps://Example[.]COM/a/../b#x` and `https://example.com/b` dedupe to one indicator.
- [ ] 1 million indicator upserts complete in under 5 minutes on a laptop, `search` p95 under 100 ms on that data (benchmark script in `tests/intel/bench.py`).
- [ ] Concurrent writers from three processes do not corrupt the database (test with `multiprocessing`).
- [ ] TLP:AMBER and above never leave the store through any export unless explicitly requested.

## Constraints
{COMMON_CONSTRAINTS}
""")))

    out.append(dict(key="store-stix-export", parent=E, milestone=M_V01,
        labels=["type:feature", "area:intel-store", "priority:p1"],
        title="STIX 2.1 export (and import) for the intel store",
        body=dedent(f"""
## Outcome
`intel_export_stix` and `cyberau-mcp store export --format stix21` produce a valid STIX 2.1 bundle that OpenCTI, MISP and Sentinel TI can ingest.

## Mapping
| Store | STIX 2.1 |
|---|---|
| indicators (ipv4/ipv6/domain/url/email/hash) | SCOs `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr`, `file` (hashes) with deterministic ids (UUIDv5 over the id contributing properties, namespace `00abedb4-aa42-466c-9c01-fed23315a9b7`, as defined in the STIX 2.1 spec) |
| verdict malicious/suspicious | `indicator` SDO with `pattern` (`[ipv4-addr:value = '1.2.3.4']`), `pattern_type: stix`, `valid_from`, `confidence`, `labels` |
| observations | `sighting` SROs or `x_cyberau_sources` on the indicator (decide in ADR; prefer sightings for analyst observations) |
| vulnerabilities | `vulnerability` SDO with `external_references` (`source_name: cve`) and `x_cyberau_kev`, `x_cyberau_epss` custom properties |
| advisories | `report` SDO with `object_refs` and `external_references` to the source URL |
| relationships | `relationship` SROs |
| producer | one `identity` SDO for the exporting organisation (name from config) |
| TLP | TLP 2.0 marking definitions as published by the OASIS CTI TC; copy the exact ids from the OASIS source and cite it in `docs/intel/stix.md` |

## Tool schema
{schema_block({"type": "object", "additionalProperties": False, "properties": {"since": {"type": "string", "format": "date"}, "kinds": {"type": "array", "items": {"enum": ["indicator", "vulnerability", "advisory"]}}, "max_tlp": {"enum": ["CLEAR", "GREEN", "AMBER"], "default": "CLEAR"}, "path": {"type": "string", "description": "Write under plugin-data/cyber-au/exports/ only"}}})}

## Acceptance criteria
- [ ] Exported bundles pass `stix2-validator` (oasis-open/cti-stix-validator) with no errors in CI.
- [ ] Export is deterministic: same store, same bundle bytes (sorted objects, fixed timestamps from data).
- [ ] Round trip: export then import yields the same indicators and verdicts.
- [ ] `max_tlp` defaults to CLEAR; AMBER needs the explicit flag and is logged in the audit log.
- [ ] Export path is confined to `plugin-data/cyber-au/exports/`.

## Constraints
{COMMON_CONSTRAINTS}
""")))

    out.append(dict(key="store-retention-snapshots", parent=E, milestone=M_V02,
        labels=["type:feature", "area:intel-store", "priority:p2"],
        title="Store retention, backups and shareable snapshots",
        body=dedent(f"""
## Outcome
The store stays small and recoverable, and a TLP:CLEAR snapshot of public data can be shipped in releases so a fresh install is useful offline.

## In scope
- Retention policy in config: observations older than N days (default 365) are compacted into indicator counters; advisories kept forever (they are small and feeds are rolling).
- `cyberau-mcp store backup` using SQLite online backup API into `plugin-data/cyber-au/backups/` with 7 daily copies.
- `cyberau-mcp store snapshot --public` writes `intel/snapshots/public-<date>.sqlite.zst` containing only public-source TLP:CLEAR data, used by the nightly refresh and release packaging.
- `cyberau-mcp store vacuum` scheduled weekly by a no-agent cron job.

## Acceptance criteria
- [ ] Snapshot contains no analyst observations and no keyed-source raw data (test).
- [ ] Restore from backup tested in CI.
- [ ] Snapshot under 50 MB compressed.

## Constraints
{COMMON_CONSTRAINTS}
""")))

    out.append(dict(key="store-duckdb-misp", parent=E, milestone=M_V10,
        labels=["type:feature", "area:intel-store", "priority:p3"],
        title="Optional DuckDB analytics export and MISP event export",
        body=dedent(f"""
## Outcome
Analysts who want SQL analytics or MISP sharing can export without changing the core store.

## In scope
- `cyberau-mcp store export --format duckdb` writes a DuckDB file with the same tables (DuckDB is an optional extra, `uv sync --extra analytics`).
- `--format misp` writes MISP JSON events (one per advisory or incident) with TLP tags.
- Docs with example queries (top KEV vendors this quarter, indicator overlap between sources).

## Acceptance criteria
- [ ] Optional extra does not affect the default install size.
- [ ] MISP JSON validates against the MISP core format schema.

## Constraints
{COMMON_CONSTRAINTS}
""")))
    return out
