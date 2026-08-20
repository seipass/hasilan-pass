CREATE TABLE attachment_uploads (
    id uuid PRIMARY KEY,
    object_id uuid NOT NULL REFERENCES vault_objects(id) ON DELETE CASCADE,
    uploader_account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    object_revision bigint NOT NULL CHECK (object_revision > 0),
    format text NOT NULL CHECK (format = 'hp-attachment.v1'),
    chunk_size integer NOT NULL CHECK (chunk_size BETWEEN 65536 AND 2097152),
    chunk_count integer NOT NULL CHECK (chunk_count BETWEEN 1 AND 100000),
    ciphertext_size bigint NOT NULL CHECK (ciphertext_size >= 16),
    state smallint NOT NULL DEFAULT 0 CHECK (state IN (0, 1)),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    expires_at timestamptz DEFAULT now() + interval '24 hours',
    CONSTRAINT attachment_state_consistent CHECK (
        (state = 0 AND completed_at IS NULL AND expires_at IS NOT NULL)
        OR (state = 1 AND completed_at IS NOT NULL AND expires_at IS NULL)
    )
);

CREATE INDEX attachment_uploads_object_idx
    ON attachment_uploads(object_id, state);
CREATE INDEX attachment_uploads_expiry_idx
    ON attachment_uploads(expires_at) WHERE state = 0;

CREATE TABLE attachment_chunks (
    attachment_id uuid NOT NULL REFERENCES attachment_uploads(id) ON DELETE CASCADE,
    chunk_index integer NOT NULL CHECK (chunk_index >= 0),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 2097168),
    ciphertext_hash bytea NOT NULL CHECK (octet_length(ciphertext_hash) = 32),
    uploaded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (attachment_id, chunk_index)
);
