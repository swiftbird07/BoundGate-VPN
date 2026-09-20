-- Tags: labels an administrator puts on nodes, to organize them and to select
-- them in policies. Part of the signed binding like roles: this column is
-- what the grant says, a node's peers believe the signature. JSON array of
-- lowercase strings, sorted.
ALTER TABLE nodes ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]';
