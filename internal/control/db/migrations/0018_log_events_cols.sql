-- The admin UI filters flow events by a handful of attributes, and every one
-- of them was a json_extract over each candidate row: on pVPN's 5.8 GB of
-- events a single filter read the whole table on the one connection, which is
-- what nodes felt as a 503 at the lookup. These five are the attributes the UI
-- actually filters on, so they become columns, filled at insert.
ALTER TABLE log_events ADD COLUMN event     TEXT;
ALTER TABLE log_events ADD COLUMN decision  TEXT;
ALTER TABLE log_events ADD COLUMN principal TEXT;
ALTER TABLE log_events ADD COLUMN dst       TEXT;
ALTER TABLE log_events ADD COLUMN owner     TEXT;

-- id descending is how the queries read (newest first, cursor on id). The
-- indexes are partial: a row whose attribute is absent -- and every row that
-- is there now, until the backfill reaches it -- stays out, which is why this
-- migration costs milliseconds instead of a minute on the startup of a control
-- plane with a 5.8 GB log (measured on 3 million rows: 350 ms against 2.7 s).
-- `WHERE x = ?` implies `WHERE x IS NOT NULL`, so the queries use them.
CREATE INDEX log_events_event_id     ON log_events (event, id)     WHERE event IS NOT NULL;
CREATE INDEX log_events_decision_id  ON log_events (decision, id)  WHERE decision IS NOT NULL;
CREATE INDEX log_events_principal_id ON log_events (principal, id) WHERE principal IS NOT NULL;
CREATE INDEX log_events_dst_id       ON log_events (dst, id)       WHERE dst IS NOT NULL;
CREATE INDEX log_events_owner_id     ON log_events (owner, id)     WHERE owner IS NOT NULL;

-- The rows that are already there are NOT filled here: on pVPN that would be
-- the whole table in one transaction while the control plane starts. Instead
-- the watermark says from where up the columns are filled, housekeeping works
-- its way down in batches (BackfillLogColumns), and a query uses the columns
-- above the mark and json_extract below it. 1 means everything is filled.
CREATE TABLE log_events_backfill (
  id        INTEGER PRIMARY KEY CHECK (id = 1),
  watermark INTEGER NOT NULL
);
INSERT INTO log_events_backfill (id, watermark) SELECT 1, COALESCE(MAX(id), 0) + 1 FROM log_events;
