---
key: "store-schema-ingest"
title: "Local threat intel store: SQLite schema, ingest API and canonical dedupe"
labels: ["type:feature", "area:intel-store", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-intel-store"
---
## Outcome
A local, single-file threat intel store that every connector, skill and routine writes to and reads from, with deterministic dedupe.

## Decision: SQLite first, DuckDB optional
SQLite (WAL, FTS5) because Hermes plugins already get a documented durable state location with a WAL SQLite option ([`website/docs/developer-guide/plugins/index.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/developer-guide/plugins/index.md), "Store durable state"), it needs no extra service, and multiple MCP processes can read it safely. DuckDB stays an optional analytics export in v1.0 (separate ticket).

Location: `<profile>/plugin-data/cyber-au/intel.sqlite`.

## Schema
```sql
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
```

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
| `intel_search` | {"query": string, "kinds": array, "since": date, "limit": int<=100} |
| `intel_get` | {"id_or_value": string, "type": string?} |
| `intel_add_observation` | {"type", "value", "verdict"?, "confidence"?, "tags"?, "tlp"?, "note"?}; records `source_id = 'analyst'` |

## Acceptance criteria
- [ ] Ingesting the same KEV catalogue twice leaves row counts unchanged.
- [ ] `hxxps://Example[.]COM/a/../b#x` and `https://example.com/b` dedupe to one indicator.
- [ ] 1 million indicator upserts complete in under 5 minutes on a laptop, `search` p95 under 100 ms on that data (benchmark script in `tests/intel/bench.py`).
- [ ] Concurrent writers from three processes do not corrupt the database (test with `multiprocessing`).
- [ ] TLP:AMBER and above never leave the store through any export unless explicitly requested.

## Constraints
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`).

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
