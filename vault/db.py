import hmac
from contextlib import contextmanager
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row

from vault.errors import VaultError, safe_event


class Database:
    def __init__(self, dsn: str):
        self._dsn = dsn

    @contextmanager
    def transaction(self):
        with psycopg.connect(
            self._dsn,
            row_factory=dict_row,
            connect_timeout=5,
            options=(
                "-c statement_timeout=10000 "
                "-c lock_timeout=3000 "
                "-c idle_in_transaction_session_timeout=30000"
            ),
        ) as connection:
            yield Repository(connection)

    def reserve_nonce(self, version: str) -> bytes:
        # Must commit before the nonce is used for encryption.
        with self.transaction() as repository:
            value = repository.reserve_nonce(version)
        return value.to_bytes(12, "big")

    def failure_audit(self, actor, document, request_id, action, code):
        try:
            with self.transaction() as repository:
                repository.audit(
                    actor, document, request_id, "access", "error", code
                )
                if action != "access":
                    repository.audit(
                        actor, document, request_id, action, "failed", code
                    )
            return True
        except psycopg.Error:
            safe_event("AUDIT_UNAVAILABLE", request_id)
            return False


class Repository:
    def __init__(self, connection):
        self._connection = connection

    def _one(self, sql, params=()):
        return self._connection.execute(sql, params).fetchone()

    def _all(self, sql, params=()):
        return self._connection.execute(sql, params).fetchall()

    def _execute(self, sql, params=()):
        self._connection.execute(sql, params)

    def now(self):
        return self._one("SELECT clock_timestamp() AS value")["value"]

    def ready(self):
        self._one("SELECT version FROM kek_registry LIMIT 1")

    def reserve_nonce(self, version):
        return self._one(
            "SELECT reserve_wrap_nonce(%s) AS value", (version,)
        )["value"]

    def verify_keys(self, fingerprints, active):
        for version, fingerprint in fingerprints.items():
            row = self._one(
                """
                SELECT fingerprint, write_enabled, wraps_issued
                FROM kek_registry WHERE version = %s
                """,
                (version,),
            )
            if row is None or not hmac.compare_digest(
                bytes(row["fingerprint"]), fingerprint
            ):
                raise VaultError("KEY_UNAVAILABLE")
            if version == active and (
                not row["write_enabled"] or row["wraps_issued"] >= 1_000_000
            ):
                raise VaultError("KEY_UNAVAILABLE")

    def provision_user(self, issuer, subject):
        user_id = uuid4()
        self._execute(
            """
            INSERT INTO users(id, issuer, subject, display_name)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (issuer, subject) DO NOTHING
            """,
            (user_id, issuer, subject, "Vault user"),
        )
        return self._one(
            "SELECT id FROM users WHERE issuer = %s AND subject = %s",
            (issuer, subject),
        )["id"]

    def lock_user(self, user_id):
        return self._one(
            "SELECT id FROM users WHERE id = %s FOR UPDATE",
            (user_id,),
        )

    def user_exists(self, user_id):
        return self._one(
            "SELECT id FROM users WHERE id = %s", (user_id,)
        ) is not None

    def usage(self, owner):
        return self._one(
            """
            SELECT
                COALESCE(SUM(plaintext_size), 0) AS size,
                COUNT(*) AS count
            FROM documents
            WHERE owner_id = %s
              AND lifecycle <> 'purged'
            """,
            (owner,),
        )

    def owner(self, document):
        return self._one(
            """
            SELECT owner_id
            FROM documents
            WHERE id = %s
              AND lifecycle = 'active'
            FOR UPDATE
            """,
            (document,),
        )

    def save_document(
        self, document, owner, filename, size, storage_ref,
        key_id, wrapped, version
    ):
        self._execute(
            """
            INSERT INTO documents(
                id, owner_id, filename, plaintext_size, storage_ref
            ) VALUES (%s, %s, %s, %s, %s)
            """,
            (document, owner, filename, size, storage_ref),
        )
        self._execute(
            """
            INSERT INTO key_metadata(
                document_id, key_id, wrapped_dek, wrap_nonce,
                algorithm, kek_version
            ) VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (document, key_id, wrapped, wrapped[:12], "AES-256-GCM", version),
        )
        self._execute(
            """
            INSERT INTO key_versions(key_id, version, kek_version, status)
            VALUES (%s, %s, %s, %s)
            """,
            (key_id, 1, version, "active"),
        )

    def metadata(self, document):
        return self._one(
            """
            SELECT
                d.id AS document_id, d.owner_id, d.filename,
                d.storage_ref, d.plaintext_size,
                k.key_id, k.wrapped_dek, k.wrap_nonce,
                k.kek_version, k.algorithm, k.current_version
            FROM documents d
            JOIN key_metadata k ON k.document_id = d.id
            WHERE d.id = %s
            """,
            (document,),
        )

    def create_grant(
        self, policy, token_id, document, owner,
        recipient, expiry, digest
    ):
        self._execute(
            """
            INSERT INTO access_policies(
                id, document_id, owner_id, recipient_id, permission, expiry
            ) VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (policy, document, owner, recipient, "read", expiry),
        )
        self._execute(
            """
            INSERT INTO access_tokens(id, policy_id, token_hash, expiry)
            VALUES (%s, %s, %s, %s)
            """,
            (token_id, policy, digest, expiry),
        )

    def token_by_hash(self, digest):
        return self._one(
            """
            SELECT
                t.id AS token_id,
                t.token_hash,
                t.revoked,
                t.expiry AS token_expiry,
                p.id AS policy_id,
                p.document_id,
                p.owner_id,
                p.recipient_id,
                p.permission,
                p.expiry AS policy_expiry
            FROM access_tokens t
            JOIN access_policies p ON p.id = t.policy_id
            JOIN documents d ON d.id = p.document_id
            WHERE t.token_hash = %s
              AND d.lifecycle = 'active'
            FOR UPDATE OF t, p, d
            """,
            (digest,),
        )

    def token_for_revoke(self, token_id):
        return self._one(
            """
            SELECT t.id, p.owner_id, p.document_id
            FROM access_tokens t
            JOIN access_policies p ON p.id = t.policy_id
            JOIN documents d ON d.id = p.document_id
            WHERE t.id = %s
            FOR UPDATE OF t, p, d
            """,
            (token_id,),
        )

    def revoke(self, token_id):
        self._execute(
            """
            UPDATE access_tokens
            SET revoked = TRUE,
                revoked_at = COALESCE(revoked_at, clock_timestamp())
            WHERE id = %s
            """,
            (token_id,),
        )

    def list_documents(self, actor, *, trash=False, limit=25, offset=0):
        return self._all(
            """
            SELECT
                id,
                filename,
                plaintext_size,
                lifecycle,
                created_at,
                deleted_at,
                purge_after
            FROM documents
            WHERE owner_id = %s
              AND lifecycle = %s
            ORDER BY created_at DESC, id DESC
            LIMIT %s OFFSET %s
            """,
            (
                actor,
                "trashed" if trash else "active",
                limit,
                offset,
            ),
        )

    def list_grants(self, document):
        return self._all(
            """
            SELECT
                p.id AS policy_id, p.recipient_id, p.permission,
                p.expiry AS policy_expiry,
                t.id AS token_id, t.expiry AS token_expiry,
                t.revoked, t.revoked_at
            FROM access_policies p
            JOIN access_tokens t ON t.policy_id = p.id
            WHERE p.document_id = %s
            ORDER BY t.issued_at DESC
            LIMIT 100
            """,
            (document,),
        )

    def list_audit(self, document):
        return self._all(
            """
            SELECT request_id, actor_id, action, result, code, "timestamp"
            FROM audit_logs
            WHERE document_id = %s
            ORDER BY id DESC
            LIMIT 100
            """,
            (document,),
        )

    def audit(self, actor, document, request_id, action, result, code):
        self._execute(
            """
            INSERT INTO audit_logs(
                actor_id, document_id, request_id, action, result, code
            ) VALUES (
                (SELECT id FROM users WHERE id = %s),
                (SELECT id FROM documents WHERE id = %s),
                %s, %s, %s, %s
            )
            """,
            (actor, document, request_id, action, result, code),
        )

    def change_lifecycle(self, actor, document, operation):
        row = self._one(
            """
            SELECT lifecycle, purge_after
            FROM documents
            WHERE id = %s AND owner_id = %s
            FOR UPDATE
            """,
            (document, actor),
        )
        if row is None or row["lifecycle"] in ("purging", "purged"):
            return False
        if operation == "trash":
            self._execute(
                """
                UPDATE documents
                SET
                    lifecycle = 'trashed',
                    deleted_at = COALESCE(deleted_at, clock_timestamp()),
                    purge_after = COALESCE(
                        purge_after,
                        clock_timestamp() + INTERVAL '7 days'
                    )
                WHERE id = %s
                """,
                (document,),
            )
            # Restoring the document must not silently restore old shares.
            self._execute(
                """
                UPDATE access_tokens
                SET
                    revoked = TRUE,
                    revoked_at = COALESCE(revoked_at, clock_timestamp())
                WHERE policy_id IN (
                    SELECT id FROM access_policies
                    WHERE document_id = %s
                )
                """,
                (document,),
            )
            return True
        if operation == "restore":
            if (
                row["lifecycle"] == "trashed"
                and row["purge_after"] <= self.now()
            ):
                return False
            self._execute(
                """
                UPDATE documents
                SET
                    lifecycle = 'active',
                    deleted_at = NULL,
                    purge_after = NULL
                WHERE id = %s
                """,
                (document,),
            )
            return True
        return False


class AdminRepository(Repository):
    """Used only by maintenance commands and test setup."""

    def register_keys(self, fingerprints):
        for version, fingerprint in fingerprints.items():
            self._execute(
                """
                INSERT INTO kek_registry(version, fingerprint)
                VALUES (%s, %s)
                ON CONFLICT (version) DO NOTHING
                """,
                (version, fingerprint),
            )
            row = self._one(
                "SELECT fingerprint FROM kek_registry WHERE version = %s",
                (version,),
            )
            if not hmac.compare_digest(bytes(row["fingerprint"]), fingerprint):
                raise VaultError("KEY_UNAVAILABLE")

    def activate(self, version):
        self._execute("UPDATE kek_registry SET write_enabled = FALSE")
        row = self._one(
            """
            UPDATE kek_registry
            SET write_enabled = TRUE
            WHERE version = %s AND wraps_issued < 1000000
            RETURNING version
            """,
            (version,),
        )
        if row is None:
            raise VaultError("KEY_UNAVAILABLE")

    def lock_metadata(self, document):
        self._one(
            "SELECT id FROM documents WHERE id = %s FOR UPDATE",
            (document,),
        )
        return self._one(
            """
            SELECT
                d.id AS document_id, d.owner_id,
                k.key_id, k.wrapped_dek, k.kek_version, k.current_version
            FROM documents d
            JOIN key_metadata k ON k.document_id = d.id
            WHERE d.id = %s
            FOR UPDATE OF k
            """,
            (document,),
        )

    def rewrap(self, row, wrapped, target):
        new_version = row["current_version"] + 1
        self._execute(
            "UPDATE key_versions SET status = %s WHERE key_id = %s AND status = %s",
            ("retired", row["key_id"], "active"),
        )
        self._execute(
            """
            INSERT INTO key_versions(key_id, version, kek_version, status)
            VALUES (%s, %s, %s, %s)
            """,
            (row["key_id"], new_version, target, "active"),
        )
        self._execute(
            """
            UPDATE key_metadata
            SET wrapped_dek = %s, wrap_nonce = %s,
                kek_version = %s, current_version = %s
            WHERE document_id = %s
            """,
            (
                wrapped, wrapped[:12], target, new_version, row["document_id"]
            ),
        )

    def documents_to_rewrap(self, target):
        return self._all(
            """
            SELECT document_id FROM key_metadata
            WHERE kek_version <> %s
            ORDER BY document_id
            """,
            (target,),
        )

    def storage_inventory(self):
        return self._all("SELECT id, storage_ref FROM documents")

    def purge_candidates(self):
        return self._all(
            """
            SELECT id
            FROM documents
            WHERE lifecycle = 'purging'
               OR (
                   lifecycle = 'trashed'
                   AND purge_after <= clock_timestamp()
               )
            ORDER BY purge_after, id
            LIMIT 100
            """
        )

    def begin_purge(self, document):
        row = self._one(
            """
            SELECT id, storage_ref, lifecycle, purge_after
            FROM documents
            WHERE id = %s
            FOR UPDATE
            """,
            (document,),
        )
        if row is None:
            return None
        eligible = (
            row["lifecycle"] == "purging"
            or (
                row["lifecycle"] == "trashed"
                and row["purge_after"] <= self.now()
            )
        )
        if not eligible:
            return None
        self._execute(
            """
            UPDATE documents
            SET lifecycle = 'purging'
            WHERE id = %s
            """,
            (document,),
        )
        return row["storage_ref"]

    def finish_purge(self, document):
        row = self._one(
            """
            SELECT lifecycle
            FROM documents
            WHERE id = %s
            FOR UPDATE
            """,
            (document,),
        )
        if row is None or row["lifecycle"] != "purging":
            return False
        self._execute(
            """
            DELETE FROM access_tokens
            WHERE policy_id IN (
                SELECT id FROM access_policies WHERE document_id = %s
            )
            """,
            (document,),
        )
        self._execute(
            "DELETE FROM access_policies WHERE document_id = %s",
            (document,),
        )
        # The current-version FK is deferred until transaction commit.
        self._execute(
            """
            DELETE FROM key_versions
            WHERE key_id IN (
                SELECT key_id FROM key_metadata WHERE document_id = %s
            )
            """,
            (document,),
        )
        self._execute(
            "DELETE FROM key_metadata WHERE document_id = %s",
            (document,),
        )
        self._execute(
            """
            UPDATE documents
            SET
                lifecycle = 'purged',
                filename = 'Deleted file',
                plaintext_size = 0,
                purged_at = clock_timestamp()
            WHERE id = %s
            """,
            (document,),
        )
        return True


class AdminDatabase(Database):
    @contextmanager
    def transaction(self):
        with psycopg.connect(
            self._dsn,
            row_factory=dict_row,
            connect_timeout=5,
            options="-c lock_timeout=3000 -c statement_timeout=10000",
        ) as connection:
            yield AdminRepository(connection)
