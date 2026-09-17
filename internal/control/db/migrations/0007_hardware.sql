-- M6: hardware_bound becomes a granted, admin-signed property of a node.
-- hardware_claimed keeps what the node reported at enrollment (unverified,
-- like the hostname); hardware_bound is what an admin granted at confirm and
-- what the signed binding, the snapshots and the policies carry.
ALTER TABLE nodes ADD COLUMN hardware_claimed INTEGER NOT NULL DEFAULT 0;
UPDATE nodes SET hardware_claimed = hardware_bound;
-- Bindings signed before M6 do not contain the field, which reads as false.
UPDATE nodes SET hardware_bound = 0 WHERE binding_sig != '';
