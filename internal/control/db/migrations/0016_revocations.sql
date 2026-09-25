-- Admin-signed revocations (binding.Revocation). Every node receives all of
-- them and refuses, for good, every binding of a revoked node that was
-- issued before its revocation, whatever the control plane serves later.
-- One per node: a newer revocation replaces the older one.
CREATE TABLE revocations (
  node_id    TEXT PRIMARY KEY,
  spki_hash  BLOB NOT NULL,
  revocation TEXT NOT NULL,
  signature  TEXT NOT NULL,
  signed_by  TEXT NOT NULL,
  created_at TEXT NOT NULL
);
