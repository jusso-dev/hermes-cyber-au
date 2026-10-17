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

-- Lookup indexes. The UNIQUE constraints above do not index observations by indicator.
CREATE INDEX observations_indicator_idx ON observations (indicator_id);
CREATE INDEX advisories_source_idx ON advisories (source_id);
