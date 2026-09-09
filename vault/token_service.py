import base64
import binascii
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import psycopg

from vault.db import Database
from vault.errors import VaultError


@dataclass(frozen=True, repr=False)
class Grant:
    policy_id: UUID
    token_id: UUID
    token: str


def new_token():
    raw = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return encoded, hashlib.sha256(raw).digest()


def hash_token(token):
    if not isinstance(token, str) or len(token) != 43:
        return None
    try:
        encoded = token.encode("ascii")
        raw = base64.b64decode(encoded + b"=", altchars=b"-_", validate=True)
    except (UnicodeError, ValueError, binascii.Error):
        return None
    if len(raw) != 32:
        return None
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=")
    if not hmac.compare_digest(canonical, encoded):
        return None
    return hashlib.sha256(raw).digest()


class TokenService:
    def __init__(self, database: Database):
        self.database = database

    def grant(self, actor, document, recipient, expiry: datetime, request_id):
        result = None
        try:
            with self.database.transaction() as repository:
                owner = repository.owner(document)
                now = repository.now()
                aware = (
                    isinstance(expiry, datetime)
                    and expiry.tzinfo is not None
                    and expiry.utcoffset() is not None
                )
                allowed = bool(
                    owner
                    and owner["owner_id"] == actor
                    and repository.user_exists(recipient)
                    and aware
                    and now < expiry <= now + timedelta(days=7)
                )
                repository.audit(
                    actor, document, request_id, "access",
                    "granted" if allowed else "denied",
                    "OK" if allowed else "ACCESS_DENIED",
                )
                if allowed:
                    policy_id, token_id = uuid4(), uuid4()
                    token, digest = new_token()
                    repository.create_grant(
                        policy_id, token_id, document, actor,
                        recipient, expiry, digest,
                    )
                    result = Grant(policy_id, token_id, token)
                repository.audit(
                    actor, document, request_id, "grant",
                    "ok" if allowed else "denied",
                    "OK" if allowed else "ACCESS_DENIED",
                )
        except psycopg.Error:
            self.database.failure_audit(
                actor, document, request_id, "grant", "DATABASE_UNAVAILABLE"
            )
            raise VaultError("DATABASE_UNAVAILABLE") from None
        if result is None:
            raise VaultError("ACCESS_DENIED")
        return result

    def revoke(self, actor, token_id, request_id):
        document = None
        allowed = False
        try:
            with self.database.transaction() as repository:
                row = repository.token_for_revoke(token_id)
                if row:
                    document = row["document_id"]
                    allowed = row["owner_id"] == actor
                repository.audit(
                    actor, document, request_id, "access",
                    "granted" if allowed else "denied",
                    "OK" if allowed else "ACCESS_DENIED",
                )
                if allowed:
                    repository.revoke(token_id)
                repository.audit(
                    actor, document, request_id, "revoke",
                    "ok" if allowed else "denied",
                    "OK" if allowed else "ACCESS_DENIED",
                )
        except psycopg.Error:
            self.database.failure_audit(
                actor, document, request_id, "revoke", "DATABASE_UNAVAILABLE"
            )
            raise VaultError("DATABASE_UNAVAILABLE") from None
        if not allowed:
            raise VaultError("ACCESS_DENIED")

    def authorize(self, repository, actor, document, token, request_id):
        digest = hash_token(token)
        row = repository.token_by_hash(digest) if digest is not None else None
        stored = bytes(row["token_hash"]) if row else bytes(32)
        supplied = digest if digest is not None else bytes(32)
        matches = hmac.compare_digest(stored, supplied)
        # Evaluate expiry after acquiring locks.
        now = repository.now()
        allowed = bool(
            row
            and digest is not None
            and matches
            and not row["revoked"]
            and row["recipient_id"] == actor
            and row["document_id"] == document
            and row["permission"] == "read"
            and now < row["token_expiry"]
            and now < row["policy_expiry"]
        )
        repository.audit(
            actor, document, request_id, "access",
            "granted" if allowed else "denied",
            "OK" if allowed else "ACCESS_DENIED",
        )
        return allowed
