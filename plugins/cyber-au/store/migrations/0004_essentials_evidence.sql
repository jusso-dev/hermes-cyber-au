-- plugins/cyber-au/store/migrations/0004_essentials_evidence.sql
-- The organisation's own evidence register for ASD Essentials actions and, kept apart,
-- Essential Eight requirements. It is a self-assessment record, not an ASD rating.
-- The two frameworks never share a row: framework is part of the key, and nothing
-- converts an Essential Eight maturity level into an Essentials result.

CREATE TABLE essentials_evidence (
  framework      TEXT NOT NULL CHECK (framework IN ('essentials','essential-eight')),
  chapter        TEXT NOT NULL,               -- essentials: enterprise-it, cloud, ot; essential-eight: strategy key
  action_id      TEXT NOT NULL,               -- essentials: GOV-01.1 (principle id, then ASD order); essential-eight: ism-1504
  status         TEXT NOT NULL CHECK (status IN ('met','partial','not met','unknown','not applicable')),
  evidence       TEXT,                        -- link or note supplied by the organisation
  owner          TEXT,
  review_date    TEXT,                        -- YYYY-MM-DD, next review due
  source         TEXT NOT NULL,               -- where the evidence came from
  evidence_date  TEXT NOT NULL,               -- YYYY-MM-DD, when the evidence was gathered
  action_sha256  TEXT,                        -- hash of the ASD text the row was recorded against
  reference_as_of TEXT,                       -- data_as_of of the ASD snapshot used
  updated_at     TEXT NOT NULL,               -- ISO 8601 UTC
  PRIMARY KEY (framework, chapter, action_id)
);
