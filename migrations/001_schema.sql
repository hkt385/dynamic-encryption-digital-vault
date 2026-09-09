BEGIN;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE TABLE users (
    id UUID PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (issuer, subject),
    CHECK (char_length(subject) BETWEEN 1 AND 255),
    CHECK (char_length(display_name) BETWEEN 1 AND 255)
);

CREATE TABLE documents (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    filename TEXT NOT NULL,
    storage_ref TEXT NOT NULL UNIQUE,
    plaintext_size BIGINT NOT NULL CHECK (plaintext_size BETWEEN 0 AND 16777216),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (id, owner_id),
    CHECK (char_length(filename) BETWEEN 1 AND 255)
);

CREATE INDEX documents_owner_idx ON documents(owner_id);
CREATE INDEX documents_created_idx ON documents(created_at);

CREATE TABLE kek_registry (
    version TEXT PRIMARY KEY,
    fingerprint BYTEA NOT NULL UNIQUE,
    write_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    wraps_issued BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (version ~ '^[A-Za-z][A-Za-z0-9_-]{0,31}$'),
    CHECK (octet_length(fingerprint) = 32),
    CHECK (wraps_issued BETWEEN 0 AND 1000000)
);

CREATE UNIQUE INDEX kek_registry_one_writer_idx
    ON kek_registry(write_enabled)
    WHERE write_enabled;

CREATE SEQUENCE kek_wrap_nonce_seq
    AS BIGINT
    START WITH 1
    INCREMENT BY 1
    MINVALUE 1
    MAXVALUE 9223372036854775807
    NO CYCLE
    CACHE 1;

CREATE TABLE key_metadata (
    document_id UUID PRIMARY KEY
        REFERENCES documents(id) ON DELETE RESTRICT,
    key_id UUID NOT NULL UNIQUE,
    wrapped_dek BYTEA NOT NULL,
    wrap_nonce BYTEA NOT NULL UNIQUE,
    algorithm TEXT NOT NULL CHECK (algorithm = 'AES-256-GCM'),
    kek_version TEXT NOT NULL
        REFERENCES kek_registry(version) ON DELETE RESTRICT,
    current_version INTEGER NOT NULL DEFAULT 1 CHECK (current_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (octet_length(wrapped_dek) = 60),
    CHECK (octet_length(wrap_nonce) = 12),
    CHECK (substring(wrapped_dek FROM 1 FOR 12) = wrap_nonce)
);

CREATE INDEX key_metadata_kek_idx ON key_metadata(kek_version);

CREATE TABLE key_versions (
    key_id UUID NOT NULL REFERENCES key_metadata(key_id) ON DELETE RESTRICT,
    version INTEGER NOT NULL CHECK (version > 0),
    kek_version TEXT NOT NULL REFERENCES kek_registry(version) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (key_id, version)
);

CREATE UNIQUE INDEX key_versions_one_active_idx
    ON key_versions(key_id)
    WHERE status = 'active';

CREATE INDEX key_versions_kek_idx ON key_versions(kek_version);

ALTER TABLE key_metadata
    ADD CONSTRAINT key_metadata_current_version_fk
    FOREIGN KEY (key_id, current_version)
    REFERENCES key_versions(key_id, version)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE access_policies (
    id UUID PRIMARY KEY,
    document_id UUID NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    permission TEXT NOT NULL CHECK (permission = 'read'),
    expiry TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (document_id, owner_id)
        REFERENCES documents(id, owner_id) ON DELETE RESTRICT
);

CREATE INDEX access_policies_document_idx ON access_policies(document_id);
CREATE INDEX access_policies_owner_idx ON access_policies(owner_id);
CREATE INDEX access_policies_recipient_idx ON access_policies(recipient_id);
CREATE INDEX access_policies_expiry_idx ON access_policies(expiry);

CREATE TABLE access_tokens (
    id UUID PRIMARY KEY,
    policy_id UUID NOT NULL REFERENCES access_policies(id) ON DELETE RESTRICT,
    token_hash BYTEA NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expiry TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (octet_length(token_hash) = 32),
    CHECK (
        (NOT revoked AND revoked_at IS NULL)
        OR (revoked AND revoked_at IS NOT NULL)
    )
);

CREATE INDEX access_tokens_policy_idx ON access_tokens(policy_id);
CREATE INDEX access_tokens_expiry_idx ON access_tokens(expiry);

CREATE TABLE audit_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    document_id UUID REFERENCES documents(id) ON DELETE SET NULL,
    request_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (
        action IN ('access', 'encrypt', 'decrypt', 'grant', 'revoke', 'rewrap')
    ),
    result TEXT NOT NULL CHECK (
        result IN ('ok', 'failed', 'granted', 'denied', 'error')
    ),
    code TEXT NOT NULL CHECK (code ~ '^[A-Z_]{1,40}$'),
    "timestamp" TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX audit_logs_actor_idx ON audit_logs(actor_id);
CREATE INDEX audit_logs_document_idx ON audit_logs(document_id);
CREATE INDEX audit_logs_request_idx ON audit_logs(request_id);
CREATE INDEX audit_logs_timestamp_idx ON audit_logs("timestamp");

CREATE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    NEW.updated_at = clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER users_updated BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER documents_updated BEFORE UPDATE ON documents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER kek_registry_updated BEFORE UPDATE ON kek_registry
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER key_metadata_updated BEFORE UPDATE ON key_metadata
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER key_versions_updated BEFORE UPDATE ON key_versions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER access_policies_updated BEFORE UPDATE ON access_policies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER access_tokens_updated BEFORE UPDATE ON access_tokens
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Runtime callers may reserve a nonce, but cannot reset the sequence,
-- decrement the counter, or activate a KEK.
CREATE FUNCTION reserve_wrap_nonce(requested_version TEXT)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    allocated BIGINT;
BEGIN
    UPDATE public.kek_registry
    SET wraps_issued = wraps_issued + 1
    WHERE version = requested_version
      AND write_enabled
      AND wraps_issued < 1000000;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Wrapping unavailable'
            USING ERRCODE = 'P0001';
    END IF;
    SELECT nextval('public.kek_wrap_nonce_seq'::regclass)
    INTO allocated;
    RETURN allocated;
END;
$$;

REVOKE ALL ON FUNCTION reserve_wrap_nonce(TEXT) FROM PUBLIC;

COMMIT;
