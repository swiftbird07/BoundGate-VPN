-- Milestone M1.6: admin-signed bindings. A node is approved only when an
-- admin key signed its binding (node id, key, key version, roles, prefixes,
-- overlay address). Approved nodes from before this migration have no
-- signature and fall back to "confirmed": they keep their grant and overlay
-- address and need a signature before peers accept them again.

ALTER TABLE nodes ADD COLUMN key_version  INTEGER NOT NULL DEFAULT 1;
ALTER TABLE nodes ADD COLUMN binding_json TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN binding_sig  TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN signed_by    TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN signed_at    TEXT;

UPDATE nodes SET status = 'confirmed', confirmed_at = approved_at, confirmed_by = approved_by,
                 approved_at = NULL, approved_by = NULL
  WHERE status = 'approved';
-- bump only when nodes were demoted, so their peers refetch
UPDATE snapshot_version SET version = version + 1
  WHERE EXISTS (SELECT 1 FROM nodes WHERE status = 'confirmed');

-- Admin signing keys (authorized_keys format, one key each). Nodes pin the
-- active set at enrollment and never update it.
CREATE TABLE admin_signers (
  id          TEXT PRIMARY KEY,
  subject     TEXT NOT NULL,            -- admin who registered it
  name        TEXT NOT NULL,
  ssh_pubkey  TEXT NOT NULL UNIQUE,     -- "type base64" without comment
  key_type    TEXT NOT NULL,
  hardware    INTEGER NOT NULL DEFAULT 0,
  fingerprint TEXT NOT NULL,            -- SHA256:...
  created_at  TEXT NOT NULL,
  revoked_at  TEXT
);

-- One-time tokens for the CLI signing step: minted by confirm, bound to the
-- node and its key, 10 minutes, single use.
CREATE TABLE sign_tokens (
  token_hash  BLOB PRIMARY KEY,
  node_id     TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  spki_hash   BLOB NOT NULL,
  admin       TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  used_at     TEXT
);
CREATE INDEX sign_tokens_node ON sign_tokens (node_id);
