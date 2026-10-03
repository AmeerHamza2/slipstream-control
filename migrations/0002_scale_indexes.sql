-- 0002: indexes and change tracking for production scale.
--
-- Every statement is IF [NOT] EXISTS. On a large live database, build the
-- indexes first without blocking writes, outside any transaction:
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS refresh_tokens_expires_idx ON refresh_tokens (expires_at);
--   ... (each CREATE INDEX below, with CONCURRENTLY)
--
-- and this migration then only records itself, creates the small tombstone
-- table and trigger, and drops the superseded index. See docs/SCALABILITY.md
-- for the measured before/after plans.

-- Janitor: "DELETE ... WHERE expires_at < $1" was a sequential scan of the
-- whole table (3.1 s on 3M rows, every hour, on every replica).
CREATE INDEX IF NOT EXISTS refresh_tokens_expires_idx ON refresh_tokens (expires_at);
-- Janitor: revoked families are dead weight a day after revocation.
CREATE INDEX IF NOT EXISTS refresh_tokens_revoked_idx ON refresh_tokens (revoked_at) WHERE revoked_at IS NOT NULL;

-- FK ON DELETE CASCADE from users: deleting one account scanned all of
-- entitlement_events (800 ms on 4.9M rows, holding a lock on the user row).
-- occurred_at second so a user's billing history reads in order.
CREATE INDEX IF NOT EXISTS entitlement_events_user_idx ON entitlement_events (user_id, occurred_at);

-- Peers: keyset pagination and "issued since" for incremental sync, ordered
-- by (created_at, device_id) per server. Supersedes the single-column index
-- (which the FK cascade from servers also used; the leading column still
-- serves it).
CREATE INDEX IF NOT EXISTS device_server_keys_server_peer_idx ON device_server_keys (server_id, created_at, device_id);
DROP INDEX IF EXISTS device_server_keys_server_idx;

-- Incremental peer sync: users whose subscription changed, or lapsed by
-- time, since the agent's last sync token.
CREATE INDEX IF NOT EXISTS subscriptions_updated_idx ON subscriptions (updated_at);
CREATE INDEX IF NOT EXISTS subscriptions_expiring_idx ON subscriptions (expires_at) WHERE status IN ('active', 'grace');

-- Peer removals for incremental sync. Written by a trigger so every path
-- that removes a key (device deleted, user deleted, server deleted, any
-- future one) records it. No foreign keys: the rows outlive what they name.
-- Pruned by the janitor after 24 h; older sync tokens get a full resync.
CREATE TABLE IF NOT EXISTS peer_tombstones (
    server_id  uuid NOT NULL,
    device_id  uuid NOT NULL,
    deleted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS peer_tombstones_server_idx ON peer_tombstones (server_id, deleted_at);
CREATE INDEX IF NOT EXISTS peer_tombstones_deleted_idx ON peer_tombstones (deleted_at);

CREATE OR REPLACE FUNCTION record_peer_tombstones() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO peer_tombstones (server_id, device_id) SELECT server_id, device_id FROM old_keys;
    RETURN NULL;
END $$;

-- Statement-level with a transition table: one INSERT per DELETE statement,
-- including the internal statements that implement ON DELETE CASCADE.
DROP TRIGGER IF EXISTS device_server_keys_tombstone ON device_server_keys;
CREATE TRIGGER device_server_keys_tombstone
    AFTER DELETE ON device_server_keys
    REFERENCING OLD TABLE AS old_keys
    FOR EACH STATEMENT EXECUTE FUNCTION record_peer_tombstones();

-- Leases for cluster-wide singleton jobs (the janitor). A row instead of a
-- session advisory lock so it works through PgBouncer in transaction mode,
-- and so "once per interval" holds across any number of replicas.
CREATE TABLE IF NOT EXISTS maintenance_leases (
    name       text PRIMARY KEY,
    holder     text NOT NULL,
    expires_at timestamptz NOT NULL
);
