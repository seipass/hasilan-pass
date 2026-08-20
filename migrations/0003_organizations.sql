ALTER TABLE accounts
    ADD COLUMN sharing_public_key text,
    ADD COLUMN protected_sharing_private_key text,
    ADD CONSTRAINT account_sharing_key_pair_consistent CHECK (
        (sharing_public_key IS NULL) = (protected_sharing_private_key IS NULL)
    );

CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    created_by uuid NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organization_members (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    account_id uuid REFERENCES accounts(id) ON DELETE SET NULL,
    email text NOT NULL CHECK (email = lower(email)),
    role smallint NOT NULL CHECK (role BETWEEN 0 AND 3),
    status smallint NOT NULL CHECK (status BETWEEN 0 AND 3),
    encrypted_organization_key text,
    invited_by uuid REFERENCES accounts(id) ON DELETE SET NULL,
    invitation_token_hash bytea UNIQUE,
    invitation_expires_at timestamptz,
    invited_at timestamptz NOT NULL DEFAULT now(),
    accepted_at timestamptz,
    confirmed_at timestamptz,
    removed_at timestamptz,
    UNIQUE (organization_id, email),
    UNIQUE (organization_id, account_id),
    CONSTRAINT organization_member_state_consistent CHECK (
        (status = 0 AND invitation_token_hash IS NOT NULL AND invitation_expires_at IS NOT NULL
            AND accepted_at IS NULL AND confirmed_at IS NULL AND removed_at IS NULL)
        OR (status = 1 AND account_id IS NOT NULL AND encrypted_organization_key IS NOT NULL
            AND accepted_at IS NOT NULL AND confirmed_at IS NULL AND removed_at IS NULL)
        OR (status = 2 AND account_id IS NOT NULL AND encrypted_organization_key IS NOT NULL
            AND accepted_at IS NOT NULL AND confirmed_at IS NOT NULL AND removed_at IS NULL)
        OR (status = 3 AND removed_at IS NOT NULL)
    )
);

CREATE INDEX organization_members_account_idx
    ON organization_members(account_id, status);
CREATE INDEX organization_members_org_status_idx
    ON organization_members(organization_id, status);

CREATE TABLE collections (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    created_by uuid NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

CREATE TABLE collection_access (
    collection_id uuid NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    member_id uuid NOT NULL REFERENCES organization_members(id) ON DELETE CASCADE,
    read_only boolean NOT NULL DEFAULT false,
    hide_passwords boolean NOT NULL DEFAULT false,
    manage boolean NOT NULL DEFAULT false,
    PRIMARY KEY (collection_id, member_id)
);

-- UUID collisions must not create ambiguous cross-account organization lookups.
CREATE UNIQUE INDEX vault_objects_global_id_uidx ON vault_objects(id);
