CREATE TABLE accounts (
    id uuid PRIMARY KEY,
    email text NOT NULL UNIQUE CHECK (email = lower(email)),
    auth_verifier text NOT NULL,
    protected_user_key text NOT NULL,
    kdf_type smallint NOT NULL CHECK (kdf_type IN (0, 1)),
    kdf_iterations integer NOT NULL CHECK (kdf_iterations > 0),
    kdf_memory_mib integer,
    kdf_parallelism integer,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

CREATE TABLE account_revisions (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    current_revision bigint NOT NULL DEFAULT 0 CHECK (current_revision >= 0)
);

CREATE TABLE devices (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    identifier uuid NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    device_type text NOT NULL CHECK (char_length(device_type) BETWEEN 1 AND 64),
    trusted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, identifier)
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_family_id uuid NOT NULL,
    access_token_hash bytea NOT NULL UNIQUE,
    refresh_token_hash bytea NOT NULL UNIQUE,
    access_expires_at timestamptz NOT NULL,
    refresh_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revoke_reason text
);

CREATE INDEX sessions_account_id_idx ON sessions(account_id);
CREATE INDEX sessions_device_id_idx ON sessions(device_id);

CREATE TABLE used_refresh_tokens (
    token_hash bytea PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    used_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE vault_objects (
    id uuid NOT NULL,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind smallint NOT NULL CHECK (kind BETWEEN 0 AND 2),
    owner_type smallint NOT NULL CHECK (owner_type IN (0, 1)),
    owner_id uuid NOT NULL,
    collection_ids uuid[] NOT NULL DEFAULT '{}',
    format text NOT NULL CHECK (char_length(format) BETWEEN 1 AND 32),
    wrapped_key text NOT NULL,
    payload text NOT NULL,
    object_revision bigint NOT NULL CHECK (object_revision > 0),
    account_revision bigint NOT NULL CHECK (account_revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    PRIMARY KEY (account_id, id)
);

CREATE INDEX vault_objects_account_revision_idx
    ON vault_objects(account_id, account_revision);
CREATE INDEX vault_objects_owner_idx
    ON vault_objects(owner_type, owner_id);

CREATE TABLE vault_changes (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    revision bigint NOT NULL,
    object_id uuid NOT NULL,
    operation smallint NOT NULL CHECK (operation IN (0, 1)),
    snapshot jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, revision)
);

CREATE INDEX vault_changes_retention_idx ON vault_changes(created_at);

CREATE TABLE idempotency_requests (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL,
    response jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, idempotency_key)
);

CREATE INDEX idempotency_expiry_idx ON idempotency_requests(created_at);

CREATE TABLE security_events (
    id uuid PRIMARY KEY,
    account_id uuid REFERENCES accounts(id) ON DELETE CASCADE,
    device_id uuid REFERENCES devices(id) ON DELETE SET NULL,
    event_type text NOT NULL CHECK (char_length(event_type) BETWEEN 1 AND 96),
    details jsonb NOT NULL DEFAULT '{}',
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX security_events_account_time_idx
    ON security_events(account_id, occurred_at DESC);

