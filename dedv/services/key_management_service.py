"""Key management: per-file key records, referenced by opaque tokens.

  * Each file has one key record in the wrapped_keys table of <vault>/config/keys.db, apart from
    the file's metadata (<vault>/metadata/vault.db) and from its ciphertext.
  * The record holds everything needed to decrypt the file (data key or, for the hybrid levels,
    the RSA private key / ML-KEM seed plus the RSA-wrapped key / KEM ciphertext). It is sealed
    with AES-256-GCM under the Vault Master Key (auth_service), so it is useless without the
    vault password or the recovery key.
  * A record is found by a random 128-bit URL-safe TOKEN. File metadata stores only that token,
    never key material.
  * The seal is bound to its owner: associated data = token, file id, algorithm id and level.
    Moving a record to another token or file, or changing the recorded algorithm or level, makes
    unwrapping fail.
  * release_key() is the only way to obtain a file's key. It refuses when the vault is locked,
    when the token is unknown or belongs to another file, and when unwrapping fails; every call
    is written to the audit log, granted or not.
"""
import base64
import json
import os
from dataclasses import dataclass, field
from secrets import token_urlsafe

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services.audit_service import DENIED, OK, AuditLog
from services.auth_service import AuthSession
from services.storage_service import VaultDb

TOKEN_BYTES = 16     # 128-bit token


class KeyStoreError(Exception):
    """Key problem; message is safe to show to the user."""


@dataclass
class ReleasedKey:
    algorithm: str                                # authenticated: part of the record's seal
    level: str
    secrets: dict = field(default_factory=dict, repr=False)
    params: dict = field(default_factory=dict, repr=False)


def _aad(token: str, file_id: str, algorithm: str, level: str) -> bytes:
    return "\x1f".join((token, file_id, algorithm, level)).encode("utf-8")


class KeyManagementService:
    def __init__(self, db: VaultDb, audit: AuditLog):
        self.db = db
        self.audit = audit

    def store_key(self, file_id: str, algorithm: str, level: str, secrets: dict[str, bytes],
                  params: dict, session: AuthSession) -> str:
        """Seal a file's key record under the VMK and return its new token."""
        token, nonce = token_urlsafe(TOKEN_BYTES), os.urandom(12)
        payload = json.dumps({"secrets": {k: base64.b64encode(v).decode() for k, v in secrets.items()},
                              "params": params}).encode()
        sealed = AESGCM(session.vmk()).encrypt(nonce, payload, _aad(token, file_id, algorithm, level))
        with self.db as conn:
            conn.execute("INSERT INTO keys.wrapped_keys VALUES (?, ?, ?, ?, ?, ?)",
                         (token, file_id, algorithm, level, nonce, sealed))
        return token

    def release_key(self, token: str, file_id: str, session: AuthSession, purpose: str = "read") -> ReleasedKey:
        """Authorization check, then unwrap. Raises KeyStoreError when refused."""
        released, level, refused = None, "", ""
        if not session.is_unlocked:
            refused = "The vault is locked. Unlock it to open files."
        else:
            with self.db as conn:
                row = conn.execute("SELECT * FROM keys.wrapped_keys WHERE token=?", (token,)).fetchone()
            if row is None:
                refused = "No key is stored for this file."
            elif row["file_id"] != file_id:
                refused = "The key reference of this file belongs to a different file."
            else:
                level = row["level"]
                try:
                    payload = json.loads(AESGCM(session.vmk()).decrypt(
                        row["nonce"], row["ct"], _aad(token, file_id, row["algorithm"], level)))
                    released = ReleasedKey(row["algorithm"], level,
                                           {k: base64.b64decode(v) for k, v in payload["secrets"].items()},
                                           payload["params"])
                except (InvalidTag, KeyError, ValueError, TypeError):
                    refused = ("The stored key for this file could not be unwrapped: "
                               "the key record was altered or belongs to another vault.")
        # Written before raising, in its own transaction, so a refusal is always recorded.
        self.audit.append("key_release", DENIED if refused else OK, file_id, level,
                          f"{purpose}: {refused}" if refused else purpose)
        if refused:
            raise KeyStoreError(refused)
        return released

    def delete(self, token: str) -> None:
        with self.db as conn:
            conn.execute("DELETE FROM keys.wrapped_keys WHERE token=?", (token,))
