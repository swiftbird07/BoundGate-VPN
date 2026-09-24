-- A list can follow a URL: the control plane fetches it every
-- source_interval seconds and replaces the entries with what it finds
-- (one entry per line or a JSON array, # comments allowed), so a list can
-- live in a Git repository next to the rest of an organisation's
-- configuration. source_header/source_secret are an optional request header
-- for a private repository; the secret is never part of an API answer.
-- source_etag is what the server last sent, so an unchanged file costs one
-- 304. source_status is empty after a fetch that worked and holds the
-- reason otherwise.
ALTER TABLE lists ADD COLUMN source_url        TEXT    NOT NULL DEFAULT '';
ALTER TABLE lists ADD COLUMN source_interval   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE lists ADD COLUMN source_header     TEXT    NOT NULL DEFAULT '';
ALTER TABLE lists ADD COLUMN source_secret     TEXT    NOT NULL DEFAULT '';
ALTER TABLE lists ADD COLUMN source_etag       TEXT    NOT NULL DEFAULT '';
ALTER TABLE lists ADD COLUMN source_fetched_at TEXT    NOT NULL DEFAULT '';
ALTER TABLE lists ADD COLUMN source_status     TEXT    NOT NULL DEFAULT '';
