"""Vault folder layout, the two SQLite databases, the cross-process lock and the metadata repository.

  <vault>/metadata/vault.db   file metadata and the audit log
  <vault>/config/keys.db      wrapped Vault Master Key and wrapped per-file key records

They are two physical files so key material is stored apart from document metadata, but they
are opened as one connection (keys.db is ATTACHed as `keys`), so a change that touches both is
one transaction. In WAL mode SQLite does not guarantee that such a transaction is atomic across
both files if the machine loses power mid-commit; writers therefore insert the key row before the
row that refers to it, so the worst case is an unreferenced key, never a file without its key.
"""
import json
import os
import sqlite3
import threading
from abc import ABC, abstractmethod
from pathlib import Path

from models.file_metadata import FileMetadata

VAULT_FOLDER = "DEDV"
SUBFOLDERS = ("encrypted_files", "metadata", "config")
VAULT_DB = Path("metadata") / "vault.db"
KEYS_DB = Path("config") / "keys.db"

# Schema steps, applied in order and recorded in schema_version. Never edit a shipped step:
# add a new (version, statements) entry instead.
MIGRATIONS = [
    (1, [   # DEDV 0.2.0
        # vault.db: one row per stored file. `token` refers to the key record in keys.db; no key
        # material is stored here.
        """CREATE TABLE IF NOT EXISTS files (
               file_id TEXT PRIMARY KEY, original_name TEXT NOT NULL, file_type TEXT NOT NULL,
               size_bytes INTEGER NOT NULL, date_added TEXT NOT NULL, security_level TEXT NOT NULL,
               encrypted_name TEXT NOT NULL, predicted_level TEXT NOT NULL DEFAULT '',
               algorithm TEXT NOT NULL, token TEXT NOT NULL DEFAULT '',
               confidence REAL, override INTEGER NOT NULL DEFAULT 0,
               model_inputs TEXT NOT NULL DEFAULT '{}')""",
        # vault.db: hash-chained audit log (audit_service).
        """CREATE TABLE IF NOT EXISTS audit_log (
               id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, action TEXT NOT NULL,
               file_id TEXT NOT NULL DEFAULT '', level TEXT NOT NULL DEFAULT '', result TEXT NOT NULL,
               detail TEXT NOT NULL DEFAULT '', prev_hash TEXT NOT NULL, hash TEXT NOT NULL)""",
        # keys.db: the Vault Master Key, wrapped under the password and under the recovery key
        # (auth_service). salt and Argon2id parameters are NULL for the recovery slot.
        """CREATE TABLE IF NOT EXISTS keys.vault_keys (
               slot TEXT PRIMARY KEY, salt BLOB, time_cost INTEGER, memory_kib INTEGER,
               parallelism INTEGER, nonce BLOB NOT NULL, wrapped_vmk BLOB NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS keys.unlock_state (
               id INTEGER PRIMARY KEY CHECK (id = 1), failed_count INTEGER NOT NULL,
               last_failed REAL NOT NULL)""",
        # keys.db: per-file key records sealed under the VMK, found by token (key_management_service).
        """CREATE TABLE IF NOT EXISTS keys.wrapped_keys (
               token TEXT PRIMARY KEY, file_id TEXT NOT NULL, algorithm TEXT NOT NULL,
               level TEXT NOT NULL, nonce BLOB NOT NULL, ct BLOB NOT NULL)""",
    ]),
]


class StorageError(Exception):
    """Message is safe to show to the user."""


def create_vault(parent: Path) -> Path:
    """Create <parent>/DEDV and its subfolders. Reuses an existing DEDV untouched."""
    parent = Path(parent)
    if not parent.is_dir():
        raise StorageError("The selected folder is not available.")
    vault = parent / VAULT_FOLDER
    try:
        for sub in SUBFOLDERS:
            (vault / sub).mkdir(parents=True, exist_ok=True)
    except PermissionError:
        raise StorageError("Permission denied. Please choose a folder you can write to.")
    except OSError as e:
        raise StorageError(f"Could not create the vault folder: {e.strerror or e}")
    return vault


class VaultLock:
    """Cross-process lock: one DEDV process per vault. The lock file is held open and locked for
    as long as the vault is open; the operating system drops it if the process dies. The same
    process may open its own vault again (counted), e.g. after changing directory and back."""
    _held: dict[str, list] = {}          # lock path -> [file descriptor, open count]
    _guard = threading.Lock()

    def __init__(self, vault_dir: Path):
        cfg = Path(vault_dir) / "config"
        cfg.mkdir(parents=True, exist_ok=True)
        self.path = str((cfg / "vault.lock").resolve())
        self._released = False
        with self._guard:
            entry = self._held.get(self.path)
            if entry:
                entry[1] += 1
                return
            try:
                fd = os.open(self.path, os.O_RDWR | os.O_CREAT)
            except OSError as e:
                raise StorageError(f"The vault could not be locked for use: {e.strerror or e}")
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                raise StorageError("This vault is already open in another DEDV window. "
                                   "Close it there first.")
            self._held[self.path] = [fd, 1]

    def release(self) -> None:
        with self._guard:
            entry = self._held.get(self.path)
            if self._released or not entry:
                return
            self._released = True
            entry[1] -= 1
            if entry[1] == 0:
                os.close(entry[0])            # closing the descriptor releases the OS lock
                del self._held[self.path]


class VaultDb:
    """The vault's SQLite connection. Use as a context manager:

        with db as conn:      # takes the thread lock and opens a transaction
            conn.execute(...)

    Blocks nest (one transaction, committed when the outermost block ends). If any block ends
    with an exception the whole transaction is rolled back. SQLite errors leave as StorageError."""

    def __init__(self, vault_dir: Path, suffix: str = "", wal: bool = True):
        vault_dir = Path(vault_dir)
        self.vault_path = Path(str(vault_dir / VAULT_DB) + suffix)
        self.keys_path = Path(str(vault_dir / KEYS_DB) + suffix)
        self._lock = threading.RLock()        # store / re-encrypt run on a worker thread
        self._depth = 0
        self._failed = False
        try:
            for p in (self.vault_path, self.keys_path):
                p.parent.mkdir(parents=True, exist_ok=True)
            # isolation_level=None: transactions are opened and closed only by __enter__/__exit__.
            self.conn = sqlite3.connect(self.vault_path, check_same_thread=False, isolation_level=None)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("ATTACH DATABASE ? AS keys", (str(self.keys_path),))
            if wal:
                self.conn.execute("PRAGMA main.journal_mode=WAL")
                self.conn.execute("PRAGMA keys.journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA busy_timeout=5000")
        except (sqlite3.Error, OSError) as e:
            raise StorageError(f"The vault database could not be opened: {e}")
        with self as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            current = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 0
            for version, statements in MIGRATIONS:
                if version > current:
                    for sql in statements:
                        conn.execute(sql)
                    conn.execute("INSERT INTO schema_version VALUES (?)", (version,))

    def __enter__(self) -> sqlite3.Connection:
        self._lock.acquire()
        try:
            if self._depth == 0:
                self._failed = False
                self.conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as e:
            self._lock.release()
            raise StorageError(f"The vault database could not be used: {e}")
        self._depth += 1
        return self.conn

    def __exit__(self, exc_type, exc, _tb):
        self._depth -= 1
        self._failed = self._failed or exc_type is not None
        try:
            if self._depth == 0:
                self.conn.execute("ROLLBACK" if self._failed else "COMMIT")
        except sqlite3.Error as e:
            raise StorageError(f"The vault database could not be updated: {e}")
        finally:
            self._lock.release()
        if exc_type is not None and issubclass(exc_type, sqlite3.Error):
            raise StorageError(f"The vault database could not be used: {exc}") from exc
        return False

    def close(self) -> None:
        with self._lock:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass


class VaultRepository(ABC):
    @abstractmethod
    def list_files(self) -> list[FileMetadata]: ...

    @abstractmethod
    def add_file(self, meta: FileMetadata) -> None: ...

    @abstractmethod
    def get_file(self, file_id: str) -> FileMetadata | None: ...

    @abstractmethod
    def update_file(self, meta: FileMetadata) -> None:
        """Replace the entry with the same file_id, atomically."""


_COLUMNS = tuple(FileMetadata.__dataclass_fields__)


def _to_row(meta: FileMetadata) -> list:
    row = {c: getattr(meta, c) for c in _COLUMNS}
    row["override"] = int(meta.override)
    row["model_inputs"] = json.dumps(meta.model_inputs)     # keeps the model's input order
    return list(row.values())


def _from_row(row: sqlite3.Row) -> FileMetadata:
    values = {c: row[c] for c in _COLUMNS}
    values["override"] = bool(values["override"])
    values["model_inputs"] = json.loads(values["model_inputs"] or "{}")
    return FileMetadata(**values)


class SqliteVaultRepository(VaultRepository):
    def __init__(self, db: VaultDb):
        self.db = db

    def list_files(self) -> list[FileMetadata]:
        with self.db as conn:
            return [_from_row(r) for r in conn.execute("SELECT * FROM files ORDER BY rowid")]

    def add_file(self, meta: FileMetadata) -> None:
        with self.db as conn:
            conn.execute(f"INSERT INTO files ({', '.join(_COLUMNS)}) "
                         f"VALUES ({', '.join('?' * len(_COLUMNS))})", _to_row(meta))

    def update_file(self, meta: FileMetadata) -> None:
        with self.db as conn:
            cur = conn.execute(f"UPDATE files SET {', '.join(c + '=?' for c in _COLUMNS)} "
                               "WHERE file_id=?", _to_row(meta) + [meta.file_id])
            if cur.rowcount == 0:
                raise StorageError("The file is no longer in the vault.")

    def get_file(self, file_id: str) -> FileMetadata | None:
        with self.db as conn:
            row = conn.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
        return _from_row(row) if row else None
