-- Housekeeping deletes log events by age every minute (PruneLogs). Without an
-- index on ts alone that was a scan of the whole table on the control plane's
-- one connection: on a 5.8 GB database it held the connection past the
-- registry lookup's 10 s, and nodes got 503 at every turn of the minute.
CREATE INDEX IF NOT EXISTS log_events_ts ON log_events (ts);
