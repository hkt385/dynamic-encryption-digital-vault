"""Vault password, Vault Master Key (VMK) and the locked / unlocked session.

Key hierarchy:
    password --Argon2id(salt, stored parameters)--> 256-bit key --AES-256-GCM--> wraps the VMK
    recovery key (256 random bits, shown once)   ----------------AES-256-GCM--> wraps the VMK
    session key (256 random bits) ---------------AES-256-GCM--> wraps the VMK (session_service)
    VMK (256 random bits) --AES-256-GCM--> wraps each file's key record (key_management_service)

Both wrapped copies of the VMK, the salt and the Argon2id parameters are in the vault_keys table
of <vault>/config/keys.db. Changing the password, or resetting it with the recovery key, re-wraps
only the VMK; no file is re-encrypted. Every password unlock starts a session bound to the Windows
sign-in (session_service); a password change or reset ends all sessions first.

While unlocked the VMK is held in a bytearray that is overwritten with zeros on lock(). This is
BEST EFFORT: Python makes immutable copies (the bytes handed to AES-GCM, the password string)
that cannot be erased, and the memory may have been paged to disk.
"""
import base64
import os
import time

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services.audit_service import FAILED, OK, AuditLog
from services.session_service import SessionStore
from services.storage_service import VaultDb

# Argon2id cost for NEW vaults and password changes. Each vault stores the values it was created
# with, so these can be raised later without breaking existing vaults.
# Calibrated 2026-11-17: median 0.40 s on a 16-thread desktop; aim is 0.5-1 s on a typical laptop.
ARGON2_TIME_COST = 6
ARGON2_MEMORY_KIB = 256 * 1024
ARGON2_PARALLELISM = 4

MIN_PASSWORD_LENGTH = 12
FREE_ATTEMPTS = 3            # wrong passwords before a delay starts
MAX_DELAY_SECONDS = 300      # the delay doubles per further failure up to this; nothing is ever erased
RECOVERY_KEY_BYTES = 32
PASSWORD_SLOT, RECOVERY_SLOT = "password", "recovery"


class AuthError(Exception):
    """Message is safe to show to the user. retry_after: seconds to wait, when throttled."""

    def __init__(self, message: str, retry_after: float = 0.0):
        super().__init__(message)
        self.retry_after = retry_after


def check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"The password must have at least {MIN_PASSWORD_LENGTH} characters. "
                        "A passphrase of several words is a good choice.")


def password_strength(password: str) -> str:
    """Rough hint for the UI, not a guarantee."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Too short ({len(password)}/{MIN_PASSWORD_LENGTH})"
    kinds = sum(any(test(c) for c in password) for test in
                (str.islower, str.isupper, str.isdigit, lambda c: not c.isalnum()))
    words = len(password.split())
    if len(set(password)) < 6:
        return "Weak: too repetitive"
    if len(password) >= 20 or words >= 4 or (len(password) >= 16 and kinds >= 3):
        return "Strong"
    if len(password) >= 14 and kinds >= 2 or kinds >= 3:
        return "Fair"
    return "Weak: add words or mix letters, digits and symbols"


def format_recovery_key(raw: bytes) -> str:
    text = base64.b32encode(raw).decode().rstrip("=")
    return "-".join(text[i:i + 4] for i in range(0, len(text), 4))


def parse_recovery_key(text: str) -> bytes:
    cleaned = "".join(c for c in text.upper() if c.isalnum())
    try:
        raw = base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except ValueError:
        raw = b""
    if len(raw) != RECOVERY_KEY_BYTES:
        raise AuthError("That is not a valid recovery key.")
    return raw


def _derive(password: str, salt: bytes, time_cost: int, memory_kib: int, parallelism: int) -> bytes:
    return hash_secret_raw(password.encode("utf-8"), salt, time_cost=time_cost, memory_cost=memory_kib,
                           parallelism=parallelism, hash_len=32, type=Type.ID)


def _aad(slot: str) -> bytes:
    return b"DEDV-VMK|" + slot.encode()


class AuthSession:
    def __init__(self, db: VaultDb, audit: AuditLog, sessions: SessionStore | None = None):
        self.db = db
        self.audit = audit
        self.sessions = sessions          # None: no sessions (e.g. the temporary upgrade database)
        self._vmk: bytearray | None = None

    # ---- state ---------------------------------------------------------------------------------
    @property
    def is_initialized(self) -> bool:
        """True once a password has been set for this vault."""
        return self._slot(PASSWORD_SLOT) is not None

    @property
    def is_unlocked(self) -> bool:
        return self._vmk is not None

    def vmk(self) -> bytes:
        if self._vmk is None:
            raise AuthError("The vault is locked.")
        return bytes(self._vmk)

    def lock(self, end_session: bool = False) -> None:
        if end_session and self.sessions is not None:
            self.sessions.end("lock")
        if self._vmk is not None:
            for i in range(len(self._vmk)):
                self._vmk[i] = 0
            self._vmk = None
            self.audit.append("lock")

    # ---- storage -------------------------------------------------------------------------------
    def _slot(self, slot: str):
        with self.db as conn:
            return conn.execute("SELECT * FROM keys.vault_keys WHERE slot=?", (slot,)).fetchone()

    def _wrap_password(self, conn, vmk: bytes, password: str) -> None:
        salt, nonce = os.urandom(16), os.urandom(12)
        key = _derive(password, salt, ARGON2_TIME_COST, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM)
        conn.execute("INSERT OR REPLACE INTO keys.vault_keys VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (PASSWORD_SLOT, salt, ARGON2_TIME_COST, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM,
                      nonce, AESGCM(key).encrypt(nonce, vmk, _aad(PASSWORD_SLOT))))

    # ---- set-up --------------------------------------------------------------------------------
    def initialize(self, password: str) -> str:
        """First run: create the VMK, wrap it under the password and under a new recovery key.
        Leaves the session unlocked and returns the recovery key (show it once; it is not stored)."""
        check_password(password)
        if self.is_initialized:
            raise AuthError("This vault already has a password.")
        vmk, recovery, nonce = os.urandom(32), os.urandom(RECOVERY_KEY_BYTES), os.urandom(12)
        with self.db as conn:
            self._wrap_password(conn, vmk, password)
            conn.execute("INSERT OR REPLACE INTO keys.vault_keys VALUES (?, NULL, NULL, NULL, NULL, ?, ?)",
                         (RECOVERY_SLOT, nonce, AESGCM(recovery).encrypt(nonce, vmk, _aad(RECOVERY_SLOT))))
            self.audit.append("password_set")
        self._vmk = bytearray(vmk)
        self._start_session(vmk)
        return format_recovery_key(recovery)

    # ---- unlock --------------------------------------------------------------------------------
    def retry_after(self) -> float:
        """Seconds until another password attempt is accepted (0 = now)."""
        with self.db as conn:
            row = conn.execute("SELECT failed_count, last_failed FROM keys.unlock_state").fetchone()
        if row is None or row["failed_count"] <= FREE_ATTEMPTS:
            return 0.0
        delay = min(2 ** (row["failed_count"] - FREE_ATTEMPTS), MAX_DELAY_SECONDS)
        return max(0.0, row["last_failed"] + delay - time.time())

    def _password_vmk(self, password: str) -> bytes:
        """Unwrap the VMK with the password, applying and recording the failed-attempt delay."""
        row = self._slot(PASSWORD_SLOT)
        if row is None:
            raise AuthError("This vault has no password yet.")
        wait = self.retry_after()
        if wait > 0:
            raise AuthError(f"Too many wrong passwords. Try again in {int(wait) + 1} s.", wait)
        key = _derive(password, row["salt"], row["time_cost"], row["memory_kib"], row["parallelism"])
        try:
            vmk = AESGCM(key).decrypt(row["nonce"], row["wrapped_vmk"], _aad(PASSWORD_SLOT))
        except InvalidTag:
            with self.db as conn:
                conn.execute("INSERT INTO keys.unlock_state (id, failed_count, last_failed) VALUES (1, 1, ?) "
                             "ON CONFLICT(id) DO UPDATE SET failed_count = failed_count + 1, "
                             "last_failed = excluded.last_failed", (time.time(),))
                self.audit.append("unlock", FAILED, detail="wrong password")
            raise AuthError("Wrong password.", self.retry_after())
        with self.db as conn:
            conn.execute("DELETE FROM keys.unlock_state")
        return vmk

    def unlock(self, password: str) -> None:
        vmk = self._password_vmk(password)
        self._vmk = bytearray(vmk)
        self.audit.append("unlock", OK)
        self._start_session(vmk)

    def resume(self) -> bool:
        """Unlock without the password if this Windows sign-in has a live session for the vault."""
        vmk = self.sessions.resume() if self.sessions is not None else None
        if vmk is None:
            return False
        self._vmk = bytearray(vmk)
        return True

    def _start_session(self, vmk: bytes, end_others: str = "") -> None:
        if self.sessions is not None:
            if end_others:
                self.sessions.end_all(end_others)
            self.sessions.start(vmk)

    def change_password(self, old_password: str, new_password: str) -> None:
        check_password(new_password)
        vmk = self._password_vmk(old_password)
        with self.db as conn:
            self._wrap_password(conn, vmk, new_password)
            self.audit.append("password_change")
        self._start_session(vmk, end_others="password change")

    def reset_with_recovery_key(self, recovery_key: str, new_password: str) -> None:
        """Forgotten password: unwrap the VMK with the recovery key, set a new password and unlock.
        The recovery key itself stays valid."""
        check_password(new_password)
        row = self._slot(RECOVERY_SLOT)
        if row is None:
            raise AuthError("This vault has no recovery key.")
        raw = parse_recovery_key(recovery_key)           # malformed input: AuthError, not logged
        try:
            vmk = AESGCM(raw).decrypt(row["nonce"], row["wrapped_vmk"], _aad(RECOVERY_SLOT))
        except InvalidTag:
            self.audit.append("recovery_use", FAILED, detail="wrong recovery key")
            raise AuthError("That recovery key does not belong to this vault.")
        with self.db as conn:
            self._wrap_password(conn, vmk, new_password)
            conn.execute("DELETE FROM keys.unlock_state")
            self.audit.append("recovery_use", OK, detail="password reset")
        self._vmk = bytearray(vmk)
        self._start_session(vmk, end_others="password reset")
