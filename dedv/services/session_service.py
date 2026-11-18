"""Sessions bound to the Windows sign-in: unlock once, stay unlocked until you sign out.

    session key (256 random bits) --AES-256-GCM--> wraps the VMK   keys.sessions (one row per computer)
    CryptProtectMemory(SAME_LOGON) --> protects the session key   <session_dir>/<vault path hash>.bin

Windows discards the CryptProtectMemory key at every restart, and only processes of the same
sign-in can decrypt it, so the cache file is useless after a restart, to another Windows account
and on another computer. The AES-GCM AAD also names the logon ID and the computer, so a session
row only opens for the sign-in that created it. The vault side can end sessions by deleting rows
(Lock, idle auto-lock, password change). Every Windows API call of DEDV's sessions is here.
"""
import ctypes
import hashlib
import os
import platform
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from paths import session_dir
from services.audit_service import DENIED, FAILED, OK, AuditLog
from services.storage_service import VaultDb

SAME_LOGON = 0x02                      # CRYPTPROTECTMEMORY_SAME_LOGON
WM_WTSSESSION_CHANGE = 0x02B1
WTS_SESSION_LOCK, WTS_SESSION_UNLOCK = 7, 8
NOTIFY_FOR_THIS_SESSION = 0
ID_BYTES, KEY_BYTES = 16, 32
_TOKEN_QUERY, _TOKEN_STATISTICS = 0x0008, 10

_available: bool | None = None


def _memory(data: bytes, function: str) -> bytes:
    from ctypes import wintypes
    fn = getattr(ctypes.WinDLL("crypt32"), function)
    fn.argtypes, fn.restype = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD], wintypes.BOOL
    buf = ctypes.create_string_buffer(bytes(data), len(data))
    if len(data) % 16 or not fn(buf, len(data), SAME_LOGON):
        raise OSError(f"{function} failed")
    return buf.raw


def protect(data: bytes) -> bytes:
    """Encrypt for this Windows sign-in until the next restart (length: a multiple of 16)."""
    return _memory(data, "CryptProtectMemory")


def unprotect(data: bytes) -> bytes:
    """Inverse of protect(). After a restart or in another sign-in it returns garbage, not an error."""
    return _memory(data, "CryptUnprotectMemory")


def logon_id() -> str:
    """ID of the Windows sign-in (logon session) this process runs in; new at every sign-in."""
    from ctypes import wintypes
    kernel32, advapi32 = ctypes.WinDLL("kernel32"), ctypes.WinDLL("advapi32")
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    token, buf, size = wintypes.HANDLE(), ctypes.create_string_buffer(64), wintypes.DWORD()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise OSError("OpenProcessToken failed")
    try:
        if not advapi32.GetTokenInformation(token, _TOKEN_STATISTICS, buf, len(buf), ctypes.byref(size)):
            raise OSError("GetTokenInformation failed")
    finally:
        kernel32.CloseHandle(token)
    low, high = int.from_bytes(buf.raw[8:12], "little"), int.from_bytes(buf.raw[12:16], "little")
    return f"{high:08x}{low:08x}"           # TOKEN_STATISTICS.AuthenticationId


def host() -> str:
    return platform.node() or "unknown"


def available() -> bool:
    """True if this system supports sessions (Windows with working CryptProtectMemory)."""
    global _available
    if _available is None:
        try:
            _available = (os.name == "nt" and unprotect(protect(bytes(KEY_BYTES))) == bytes(KEY_BYTES)
                          and bool(logon_id()))
        except (OSError, AttributeError, ValueError):
            _available = False
    return _available


def _aad(session_id: str, logon: str, computer: str) -> bytes:
    return f"DEDV session|{session_id}|{logon}|{computer}".encode()


class SessionStore:
    def __init__(self, db: VaultDb, audit: AuditLog, vault_dir: Path):
        self.db, self.audit = db, audit
        name = hashlib.sha256(str(Path(vault_dir).resolve()).lower().encode()).hexdigest()[:32]
        self.cache_path = session_dir() / f"{name}.bin"

    def start(self, vmk: bytes) -> None:
        """Start a session for this sign-in (replaces this computer's previous one). Never raises:
        if it fails the vault simply asks for the password next time."""
        if not available():
            return
        session_id, key, nonce = os.urandom(ID_BYTES).hex(), os.urandom(KEY_BYTES), os.urandom(12)
        try:
            logon, computer = logon_id(), host()
            blob = bytes.fromhex(session_id) + protect(key)
            with self.db as conn:
                conn.execute("INSERT OR REPLACE INTO keys.sessions VALUES (?, ?, ?, ?, ?, ?)",
                             (computer, session_id, logon, datetime.now(timezone.utc).isoformat(timespec="seconds"),
                              nonce, AESGCM(key).encrypt(nonce, vmk, _aad(session_id, logon, computer))))
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                self.cache_path.write_bytes(blob)       # a failure rolls the row back
                self.audit.append("session_start", OK)
        except (OSError, ValueError) as e:
            self.cache_path.unlink(missing_ok=True)
            self.audit.append("session_start", FAILED, detail=type(e).__name__)

    def resume(self) -> bytes | None:
        """The VMK if this sign-in has a live session for the vault, else None (refusals audited)."""
        try:
            blob = self.cache_path.read_bytes()
        except FileNotFoundError:
            return None                                  # no session: nothing to refuse
        except OSError:
            blob = b""
        reason, row, session_id = "restarted or altered", None, None
        if len(blob) == ID_BYTES + KEY_BYTES:
            session_id = blob[:ID_BYTES].hex()
            with self.db as conn:
                row = conn.execute("SELECT * FROM keys.sessions WHERE host=?", (host(),)).fetchone()
            if row is None or row["session_id"] != session_id:
                reason, row = "ended", None
            elif row["logon_id"] != logon_id():
                reason = "other sign-in"
            else:
                try:
                    key = unprotect(blob[ID_BYTES:])
                    vmk = AESGCM(key).decrypt(row["nonce"], row["wrapped_vmk"],
                                              _aad(session_id, row["logon_id"], row["host"]))
                    self.audit.append("session_resume", OK)
                    return vmk
                except (InvalidTag, OSError, ValueError):
                    pass
        with self.db as conn:                            # a refused session is gone for good
            if row is not None:
                conn.execute("DELETE FROM keys.sessions WHERE host=? AND session_id=?", (row["host"], session_id))
            self.cache_path.unlink(missing_ok=True)
            self.audit.append("session_resume", DENIED, detail=reason)
        return None

    def end(self, reason: str) -> None:
        """End this computer's session (Lock button, idle auto-lock)."""
        self._delete("DELETE FROM keys.sessions WHERE host=?", (host(),), reason)

    def end_all(self, reason: str) -> None:
        """End every session of the vault, on every computer (password change or reset)."""
        self._delete("DELETE FROM keys.sessions", (), reason)

    def _delete(self, sql: str, args: tuple, reason: str) -> None:
        with self.db as conn:
            removed = conn.execute(sql, args).rowcount > 0
            if self.cache_path.exists():
                self.cache_path.unlink()
                removed = True
            if removed:
                self.audit.append("session_end", OK, detail=reason)
