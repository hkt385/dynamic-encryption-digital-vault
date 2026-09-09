-- Run once as the database administrator.
BEGIN;

CREATE ROLE vault_app NOLOGIN;
CREATE ROLE vault_audit_reader NOLOGIN;
CREATE ROLE vault_runtime
    LOGIN
    INHERIT
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    IN ROLE vault_app;

GRANT USAGE ON SCHEMA public TO vault_app, vault_audit_reader;

GRANT SELECT, INSERT ON
    users,
    documents,
    key_metadata,
    key_versions,
    access_policies,
    access_tokens
TO vault_app;

GRANT SELECT ON kek_registry TO vault_app;

GRANT UPDATE (revoked, revoked_at)
    ON access_tokens TO vault_app;

-- SELECT ... FOR UPDATE requires UPDATE privilege.
-- Grant only an innocuous column; service code never changes it.
GRANT UPDATE (updated_at) ON
    users,
    documents,
    access_policies
TO vault_app;

GRANT INSERT ON audit_logs TO vault_app;
GRANT USAGE ON SEQUENCE audit_logs_id_seq TO vault_app;
GRANT EXECUTE ON FUNCTION reserve_wrap_nonce(TEXT) TO vault_app;

GRANT SELECT ON audit_logs TO vault_audit_reader;

-- Permission adjustment: the API must be able to read audit rows before
-- applying its own owner check at the application layer. This preserves
-- insert-only mutation: the runtime still cannot update or delete audits.
GRANT SELECT ON audit_logs TO vault_app;

COMMIT;
