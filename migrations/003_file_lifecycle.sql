BEGIN;

ALTER TABLE documents
    ADD COLUMN lifecycle TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN deleted_at TIMESTAMPTZ,
    ADD COLUMN purge_after TIMESTAMPTZ,
    ADD COLUMN purged_at TIMESTAMPTZ;

ALTER TABLE documents
    ADD CONSTRAINT documents_lifecycle_check
    CHECK (lifecycle IN ('active', 'trashed', 'purging', 'purged'));

ALTER TABLE documents
    ADD CONSTRAINT documents_lifecycle_timestamps_check
    CHECK (
        (
            lifecycle = 'active'
            AND deleted_at IS NULL
            AND purge_after IS NULL
            AND purged_at IS NULL
        )
        OR
        (
            lifecycle IN ('trashed', 'purging')
            AND deleted_at IS NOT NULL
            AND purge_after IS NOT NULL
            AND purged_at IS NULL
        )
        OR
        (
            lifecycle = 'purged'
            AND deleted_at IS NOT NULL
            AND purge_after IS NOT NULL
            AND purged_at IS NOT NULL
            AND plaintext_size = 0
        )
    );

CREATE INDEX documents_owner_lifecycle_created_idx
    ON documents(owner_id, lifecycle, created_at DESC, id DESC);

CREATE INDEX documents_purge_idx
    ON documents(purge_after)
    WHERE lifecycle IN ('trashed', 'purging');

ALTER TABLE audit_logs
    DROP CONSTRAINT audit_logs_action_check;

ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_action_check
    CHECK (
        action IN (
            'access', 'encrypt', 'decrypt', 'grant',
            'revoke', 'rewrap', 'trash', 'restore', 'purge'
        )
    );

GRANT UPDATE (
    lifecycle,
    deleted_at,
    purge_after
) ON documents TO vault_app;

COMMIT;
