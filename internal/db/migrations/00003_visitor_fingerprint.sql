-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE visitors ADD COLUMN IF NOT EXISTS fingerprint TEXT;

-- Backfill with the same fingerprint formula used by the Go visitor store.
UPDATE visitors
SET fingerprint = encode(
  digest(
    visitor_id || E'\x1f' || ip || E'\x1f' || country || E'\x1f' || city || E'\x1f' || user_agent || E'\x1f' || referer,
    'sha256'
  ),
  'hex'
)
WHERE fingerprint IS NULL OR fingerprint = '';

ALTER TABLE visitors ALTER COLUMN fingerprint SET NOT NULL;

ALTER TABLE visitors DROP CONSTRAINT IF EXISTS visitors_pkey;
ALTER TABLE visitors ADD PRIMARY KEY (fingerprint);

CREATE INDEX IF NOT EXISTS visitors_visitor_id_idx ON visitors (visitor_id);
CREATE INDEX IF NOT EXISTS visitors_ip_idx ON visitors (ip);

-- +goose Down
ALTER TABLE visitors DROP CONSTRAINT IF EXISTS visitors_pkey;
DROP INDEX IF EXISTS visitors_visitor_id_idx;
DROP INDEX IF EXISTS visitors_ip_idx;
ALTER TABLE visitors DROP COLUMN IF EXISTS fingerprint;
ALTER TABLE visitors ADD PRIMARY KEY (visitor_id);
