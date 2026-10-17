-- plugins/cyber-au/store/migrations/0002_retention.sql
-- Folded observation totals. Advisories are not stored here.

ALTER TABLE sources ADD COLUMN keyed INTEGER NOT NULL DEFAULT 0;

CREATE TABLE indicator_counters (
  indicator_id   TEXT NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
  source_id      TEXT NOT NULL REFERENCES sources(id),
  verdict        TEXT NOT NULL CHECK (verdict IN ('malicious','suspicious','benign','unknown')),
  observations   INTEGER NOT NULL CHECK (observations > 0),
  confidence_sum INTEGER NOT NULL CHECK (confidence_sum >= 0),
  first_seen     TEXT NOT NULL,
  last_seen      TEXT NOT NULL,
  PRIMARY KEY (indicator_id, source_id, verdict)
);

CREATE INDEX indicator_counters_indicator_idx ON indicator_counters (indicator_id);
