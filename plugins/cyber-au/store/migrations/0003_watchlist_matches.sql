-- plugins/cyber-au/store/migrations/0003_watchlist_matches.sql
-- Current watchlist matches. Every run recomputes this table from what is in the store
-- now, so a row never outlives the indicator or advisory it points at.

CREATE TABLE watchlist_matches (
  list          TEXT NOT NULL,               -- domains, brands, ip_ranges, asns, vendors
  kind          TEXT NOT NULL,               -- domain, lookalike, ip_range, asn, brand, vendor
  value         TEXT NOT NULL,               -- the watchlist entry that matched
  ref_kind      TEXT NOT NULL,               -- indicator, advisory, crtsh
  ref           TEXT NOT NULL,               -- indicator id, advisory id or certificate name
  matched       TEXT NOT NULL,               -- the stored value that matched
  detail        TEXT,
  first_matched TEXT NOT NULL,               -- ISO 8601 UTC
  last_matched  TEXT NOT NULL,
  PRIMARY KEY (list, value, ref_kind, ref)
);

CREATE INDEX watchlist_matches_first_idx ON watchlist_matches (first_matched);
CREATE INDEX watchlist_matches_ref_idx ON watchlist_matches (ref_kind, ref);

-- No foreign keys: a match may point at either table. These triggers drop a match as soon
-- as its store row goes, so nothing reads a match for data that has expired.
CREATE TRIGGER watchlist_matches_indicator_gone AFTER DELETE ON indicators
BEGIN
  DELETE FROM watchlist_matches WHERE ref_kind = 'indicator' AND ref = OLD.id;
END;

CREATE TRIGGER watchlist_matches_advisory_gone AFTER DELETE ON advisories
BEGIN
  DELETE FROM watchlist_matches WHERE ref_kind = 'advisory' AND ref = OLD.id;
END;
