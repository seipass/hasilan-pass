-- Account second factors are intentionally separate from zero-knowledge vault data.
-- The TOTP seed is encrypted with HP_MFA_ENCRYPTION_KEY before it reaches this table.
CREATE TABLE account_totp (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    encrypted_secret text NOT NULL,
    last_used_step bigint NOT NULL DEFAULT -1,
    enabled_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE account_totp_setups (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    session_id uuid REFERENCES sessions(id) ON DELETE CASCADE,
    encrypted_secret text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    UNIQUE (account_id)
);

CREATE INDEX account_totp_setups_expiry_idx ON account_totp_setups(expires_at);

-- Recovery codes have 80 bits of CSPRNG entropy and are stored only as keyed hashes.
CREATE TABLE account_recovery_codes (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at timestamptz,
    UNIQUE (account_id, code_hash)
);

CREATE INDEX account_recovery_codes_available_idx
    ON account_recovery_codes(account_id) WHERE used_at IS NULL;

-- Passkey contains only credential public material and authenticator metadata.
CREATE TABLE account_webauthn_credentials (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    passkey jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);

CREATE INDEX account_webauthn_credentials_account_idx
    ON account_webauthn_credentials(account_id);

-- The serialised webauthn-rs state never leaves the server. Rows are single-use and
-- database-backed so replay protection survives restarts and multiple replicas.
CREATE TABLE webauthn_ceremonies (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    session_id uuid REFERENCES sessions(id) ON DELETE CASCADE,
    purpose smallint NOT NULL CHECK (purpose IN (0, 1, 2)),
    state jsonb NOT NULL,
    credential_name text CHECK (credential_name IS NULL OR char_length(credential_name) BETWEEN 1 AND 128),
    device_identifier uuid,
    device_name text,
    device_type text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (
        (purpose = 0 AND session_id IS NOT NULL AND credential_name IS NOT NULL AND device_identifier IS NULL AND device_name IS NULL AND device_type IS NULL)
        OR
        (purpose IN (1, 2) AND session_id IS NULL AND credential_name IS NULL AND device_identifier IS NOT NULL AND device_name IS NOT NULL AND device_type IS NOT NULL)
    )
);

CREATE INDEX webauthn_ceremonies_expiry_idx ON webauthn_ceremonies(expires_at);

ALTER TABLE devices
    ADD COLUMN trusted_token_hash bytea,
    ADD COLUMN trusted_until timestamptz,
    ADD CONSTRAINT devices_trust_consistency CHECK (
        (trusted = false AND trusted_token_hash IS NULL AND trusted_until IS NULL)
        OR
        (trusted = true AND trusted_token_hash IS NOT NULL AND trusted_until IS NOT NULL)
    );
