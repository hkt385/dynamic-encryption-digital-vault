from dataclasses import dataclass
from uuid import uuid4

import psycopg
from cryptography.exceptions import InvalidTag

from vault import encryption_service as crypto
from vault.errors import VaultError
from vault.token_service import TokenService

USER_QUOTA_BYTES = 100 * 1024 * 1024
USER_DOCUMENT_LIMIT = 1000


@dataclass(frozen=True, repr=False)
class Download:
    data: bytes
    filename: str


class KeyManager:
    def __init__(self, database, storage, keys):
        self.database = database
        self.storage = storage
        self.keys = keys
        self.tokens = TokenService(database)
        with database.transaction() as repository:
            repository.verify_keys(keys.fingerprints(), keys.active)

    def encrypt(self, actor, filename, plaintext, request_id):
        document = uuid4()
        failure = None
        try:
            if (
                not isinstance(filename, str)
                or not 1 <= len(filename) <= 255
                or any(ord(character) < 32 or ord(character) == 127 for character in filename)
                or not isinstance(plaintext, bytes)
            ):
                raise VaultError("INVALID_REQUEST")
            if len(plaintext) > crypto.MAX_FILE_BYTES:
                raise VaultError("FILE_TOO_LARGE")
            with self.database.transaction() as repository:
                known = repository.lock_user(actor)
                if not known:
                    failure = "ACCESS_DENIED"
                else:
                    usage = repository.usage(actor)
                    if (
                        usage["size"] + len(plaintext) > USER_QUOTA_BYTES
                        or usage["count"] >= USER_DOCUMENT_LIMIT
                    ):
                        failure = "QUOTA_EXCEEDED"
                repository.audit(
                    actor, None, request_id, "access",
                    "denied" if failure else "granted",
                    failure or "OK",
                )
                if failure:
                    repository.audit(
                        actor, None, request_id, "encrypt", "denied", failure
                    )
                else:
                    key_id = uuid4()
                    dek = crypto.generate_dek()
                    encrypted = crypto.encrypt_file(
                        plaintext,
                        dek,
                        crypto.file_aad(document, actor, key_id),
                    )
                    # A separate transaction commits this reservation.
                    nonce = self.database.reserve_nonce(self.keys.active)
                    wrapped = crypto.wrap_dek(
                        dek,
                        self.keys.get_key(self.keys.active),
                        nonce,
                        crypto.key_aad(document, actor, key_id, self.keys.active),
                    )
                    del dek
                    reference = self.storage.write(document, encrypted)
                    repository.save_document(
                        document, actor, filename, len(plaintext),
                        reference, key_id, wrapped, self.keys.active,
                    )
                    repository.audit(
                        actor, document, request_id, "encrypt", "ok", "OK"
                    )
        except VaultError as error:
            self.database.failure_audit(
                actor, document, request_id, "encrypt", error.code
            )
            raise
        except (psycopg.Error, OSError, ValueError):
            self.database.failure_audit(
                actor, document, request_id, "encrypt", "UPLOAD_FAILED"
            )
            # Retain a possible encrypted orphan after ambiguous COMMIT.
            raise VaultError("UPLOAD_FAILED") from None
        if failure:
            raise VaultError(failure)
        return document

    def decrypt(self, actor, document, token, request_id):
        download = None
        failure = None
        try:
            with self.database.transaction() as repository:
                if token is None:
                    owner = repository.owner(document)
                    allowed = bool(owner and owner["owner_id"] == actor)
                    repository.audit(
                        actor,
                        document,
                        request_id,
                        "access",
                        "granted" if allowed else "denied",
                        "OK" if allowed else "ACCESS_DENIED",
                    )
                else:
                    allowed = self.tokens.authorize(
                        repository,
                        actor,
                        document,
                        token,
                        request_id,
                    )
                if not allowed:
                    failure = "ACCESS_DENIED"
                else:
                    try:
                        row = repository.metadata(document)
                        if row is None or row["algorithm"] != crypto.ALGORITHM:
                            raise ValueError()
                        dek = crypto.unwrap_dek(
                            bytes(row["wrapped_dek"]),
                            self.keys.get_key(row["kek_version"]),
                            crypto.key_aad(
                                document, row["owner_id"],
                                row["key_id"], row["kek_version"],
                            ),
                        )
                        encrypted = self.storage.read(document, row["storage_ref"])
                        plaintext = crypto.decrypt_file(
                            encrypted,
                            dek,
                            crypto.file_aad(
                                document, row["owner_id"], row["key_id"]
                            ),
                        )
                        del dek
                        download = Download(plaintext, row["filename"])
                    except VaultError:
                        failure = "KEY_UNAVAILABLE"
                    except (InvalidTag, ValueError, OSError):
                        failure = "DECRYPTION_FAILED"
                repository.audit(
                    actor, document, request_id, "decrypt",
                    "denied" if failure == "ACCESS_DENIED"
                    else "failed" if failure
                    else "ok",
                    failure or "OK",
                )
            # Never return plaintext until the audit transaction commits.
        except psycopg.Error:
            download = None
            self.database.failure_audit(
                actor, document, request_id, "decrypt", "DATABASE_UNAVAILABLE"
            )
            raise VaultError("DATABASE_UNAVAILABLE") from None
        if failure:
            raise VaultError(failure)
        if download is None:
            raise VaultError("DECRYPTION_FAILED")
        return download
