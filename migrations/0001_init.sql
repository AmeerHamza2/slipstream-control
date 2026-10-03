-- Accounts ---------------------------------------------------------------
CREATE TABLE users (
    id            uuid PRIMARY KEY,
    email         text NOT NULL,
    password_hash text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_email_lower CHECK (email = lower(email))
);

-- Refresh tokens: only SHA-256(token) is stored. A family is one login
-- session; every rotation adds a row to the family and marks the previous
-- one rotated. Presenting a rotated token revokes the whole family.
CREATE TABLE refresh_tokens (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id   uuid NOT NULL,
    token_hash  bytea NOT NULL,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    rotated_at  timestamptz,
    revoked_at  timestamptz,
    CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash)
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id);

-- Devices and WireGuard IPAM ---------------------------------------------
CREATE TABLE devices (
    id            uuid PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name          text NOT NULL,
    platform      text NOT NULL,
    wg_public_key text NOT NULL,
    tunnel_ip     inet NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT devices_platform_check CHECK (platform IN ('android', 'ios')),
    CONSTRAINT devices_wg_public_key_key UNIQUE (wg_public_key),
    -- The unique constraint is what makes allocation race-safe.
    CONSTRAINT devices_tunnel_ip_key UNIQUE (tunnel_ip),
    CONSTRAINT devices_tunnel_ip_pool CHECK (
        family(tunnel_ip) = 4 AND masklen(tunnel_ip) = 32
        AND tunnel_ip << inet '10.64.0.0/10'
        AND tunnel_ip NOT IN (inet '10.64.0.0', inet '10.64.0.1'))
);
CREATE INDEX devices_user_idx ON devices (user_id);

-- Servers and health -----------------------------------------------------
CREATE TABLE servers (
    id                      uuid PRIMARY KEY,
    name                    text NOT NULL,
    country                 text NOT NULL,
    city                    text NOT NULL,
    public_ipv4             inet NOT NULL,
    wg_port                 integer NOT NULL,
    wg_public_key           text NOT NULL,
    ss_port                 integer NOT NULL,
    ss_master_secret_enc    text NOT NULL,           -- "v1:" AES-256-GCM envelope
    created_at              timestamptz NOT NULL DEFAULT now(),
    healthy                 boolean NOT NULL DEFAULT false,
    consecutive_reachable   integer NOT NULL DEFAULT 0,
    consecutive_unreachable integer NOT NULL DEFAULT 0,
    last_heartbeat_at       timestamptz,
    rtt_ms_p50              double precision,
    rtt_ms_p95              double precision,
    loss                    double precision,
    load                    double precision,
    CONSTRAINT servers_name_key UNIQUE (name),
    CONSTRAINT servers_country_check CHECK (country ~ '^[A-Z]{2}$'),
    CONSTRAINT servers_wg_port_check CHECK (wg_port BETWEEN 1 AND 65535),
    CONSTRAINT servers_ss_port_check CHECK (ss_port BETWEEN 1 AND 65535),
    CONSTRAINT servers_ipv4_check CHECK (family(public_ipv4) = 4 AND masklen(public_ipv4) = 32)
);

-- Per (device, server) WireGuard preshared keys, generated on first config
-- issuance and stored encrypted.
CREATE TABLE device_server_keys (
    device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    server_id   uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    psk_enc     text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, server_id)
);
CREATE INDEX device_server_keys_server_idx ON device_server_keys (server_id);

-- Entitlements -----------------------------------------------------------
-- Every event ever received (idempotency on event_id + audit trail).
CREATE TABLE entitlement_events (
    event_id                text PRIMARY KEY,
    source                  text NOT NULL,
    user_id                 uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    product_id              text NOT NULL,
    status                  text NOT NULL,
    expires_at              timestamptz,
    original_transaction_id text NOT NULL,
    occurred_at             timestamptz NOT NULL,
    received_at             timestamptz NOT NULL DEFAULT now(),
    applied                 boolean NOT NULL,
    reason                  text
);

-- Latest applied state per store subscription.
CREATE TABLE subscriptions (
    source                  text NOT NULL,
    original_transaction_id text NOT NULL,
    user_id                 uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    product_id              text NOT NULL,
    status                  text NOT NULL,
    expires_at              timestamptz,
    last_event_id           text NOT NULL,
    last_event_at           timestamptz NOT NULL,
    updated_at              timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source, original_transaction_id),
    CONSTRAINT subscriptions_source_check CHECK (source IN ('stripe', 'app_store', 'google_play')),
    CONSTRAINT subscriptions_status_check CHECK (status IN ('active', 'grace', 'expired', 'revoked', 'refunded'))
);
CREATE INDEX subscriptions_user_idx ON subscriptions (user_id);
