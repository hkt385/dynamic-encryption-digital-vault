import psycopg
from psycopg.rows import dict_row


class TestAdmin:
    __test__ = False

    def __init__(self, dsn):
        self.dsn = dsn

    def execute(self, sql, params=()):
        with psycopg.connect(self.dsn, row_factory=dict_row) as connection:
            cursor = connection.execute(sql, params)
            return cursor.fetchall() if cursor.description else []

    def expire_token(self, token_id):
        self.execute(
            """
            UPDATE access_tokens
            SET expiry = clock_timestamp() - INTERVAL '1 second'
            WHERE id = %s
            """,
            (token_id,),
        )

    def expire_policy(self, policy_id):
        self.execute(
            """
            UPDATE access_policies
            SET expiry = clock_timestamp() - INTERVAL '1 second'
            WHERE id = %s
            """,
            (policy_id,),
        )

    def tamper_wrapped_key(self, document, wrapped):
        self.execute(
            "UPDATE key_metadata SET wrapped_dek = %s WHERE document_id = %s",
            (wrapped, document),
        )

    def events(self, document):
        return self.execute(
            """
            SELECT action, result, code FROM audit_logs
            WHERE document_id = %s ORDER BY id
            """,
            (document,),
        )

    def fail_audit_for(self, request_id):
        # The setting is held in a test-only table rather than SQL interpolation.
        self.execute(
            """
            CREATE TABLE IF NOT EXISTS test_failed_audit_requests (
                request_id UUID PRIMARY KEY
            )
            """
        )
        self.execute(
            """
            CREATE OR REPLACE FUNCTION test_reject_audit()
            RETURNS TRIGGER
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog
            AS $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM public.test_failed_audit_requests
                    WHERE request_id = NEW.request_id
                ) THEN
                    RAISE EXCEPTION 'Test audit failure';
                END IF;
                RETURN NEW;
            END;
            $$
            """
        )
        self.execute("DROP TRIGGER IF EXISTS test_reject_audit ON audit_logs")
        self.execute(
            """
            CREATE TRIGGER test_reject_audit
            BEFORE INSERT ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION test_reject_audit()
            """
        )
        self.execute(
            "INSERT INTO test_failed_audit_requests VALUES (%s)",
            (request_id,),
        )

    def clear_audit_failure(self, request_id):
        self.execute(
            "DELETE FROM test_failed_audit_requests WHERE request_id = %s",
            (request_id,),
        )
