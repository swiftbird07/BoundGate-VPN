-- A user login counts only after the person confirmed it in the browser
-- (R120). The callback stores the verified identity on the flow (status
-- confirm) and shows which device is about to be signed in; only the
-- button on that page, which carries a single-use token whose hash is kept
-- in confirm_hash, completes the flow. start_ip is where the node started
-- the flow from, callback_ip where the browser came back from the identity
-- provider. Flows live ten minutes: the table is rebuilt for the new
-- status and a login that was in flight during the upgrade starts again.
DROP TABLE login_flows;
CREATE TABLE login_flows (
  id                 TEXT PRIMARY KEY,
  node_id            TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  state              TEXT NOT NULL UNIQUE,
  nonce              TEXT NOT NULL,
  pkce_verifier      TEXT NOT NULL,
  created_at         TEXT NOT NULL,
  expires_at         TEXT NOT NULL,
  status             TEXT NOT NULL CHECK (status IN ('pending', 'confirm', 'done', 'failed')),
  session_id         TEXT,
  error              TEXT NOT NULL DEFAULT '',
  start_ip           TEXT NOT NULL DEFAULT '',
  callback_ip        TEXT NOT NULL DEFAULT '',
  identity_json      TEXT NOT NULL DEFAULT '',
  confirm_hash       BLOB,
  confirm_expires_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX login_flows_node ON login_flows (node_id);
