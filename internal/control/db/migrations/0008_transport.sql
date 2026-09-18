-- M8.2: which transport a tunnel runs on, as the hub reports it: quic
-- (UDP/443) or tcp (the fallback on TCP/443 for networks that block UDP).
-- Empty for records from hubs older than this migration.
ALTER TABLE tunnels ADD COLUMN transport TEXT NOT NULL DEFAULT '';
