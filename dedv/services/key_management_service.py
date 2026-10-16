"""Key management: the DEDV development key-encryption key (KEK) + wrapped per-file secrets.

DEVELOPMENT STAND-IN, not production key storage:
  * The KEK (key id "DEDV") is 32 random bytes in a plaintext text file, DEDV_key.txt, in a
    local folder outside the vault and outside the installer (paths.key_dir()).
  * Per-file secrets (AES / ChaCha20 data keys, RSA private key, ML-KEM seed) are never stored
    in the clear: each record is sealed with AES-256-GCM under the KEK (associated data = key
    reference) and kept in <vault>/config/wrapped_keys.json.
  * Vault entries created before this design used plaintext keys in <vault>/config/dev_keys.json;
    they are still readable (legacy) and are migrated when re-encrypted.
"""
import base64
import json
import os
import subprocess
import threading
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from paths import key_dir

KEK_ID = "DEDV"
KEY_FILE_NAME = "DEDV_key.txt"
KEY_BYTES = 32


class KeyStoreError(Exception):
    """Key problem; message is safe to show to the user."""


def _restrict_permissions(path: Path) -> bool:
    """Best effort: owner-only access. Returns True if applied."""
    try:
        if os.name == "nt":
            user = os.environ.get("USERNAME")
            if not user:
                return False
            grant = f"{user}:(OI)(CI)F" if path.is_dir() else f"{user}:F"
            # Owner only: drop inherited ACEs and the default explicit Administrators / SYSTEM
            # entries (well-known SIDs, so this works on any Windows language).
            r = subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", grant,
                                "/remove:g", "*S-1-5-32-544", "*S-1-5-18"],
                               capture_output=True, timeout=15,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return r.returncode == 0
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


class DevKeyFile:
    """Reads/creates <key_dir>/DEDV_key.txt. Never overwrites an existing file."""

    def __init__(self, directory: Path | None = None):
        self.dir = Path(directory) if directory else key_dir()
        self.path = self.dir / KEY_FILE_NAME
        self.permissions_restricted = False

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> bytes:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise KeyStoreError(f"The DEDV key file is missing: {self.path}")
        except OSError as e:
            raise KeyStoreError(f"The DEDV key file could not be read ({e.strerror or e}): {self.path}")
        fields = {}
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and ":" in line:
                k, v = line.split(":", 1)
                fields[k.strip().lower()] = v.strip()
        if fields.get("key_id") != KEK_ID:
            raise KeyStoreError(f"The DEDV key file is malformed (key_id must be {KEK_ID}): {self.path}")
        try:
            key = base64.b64decode(fields.get("key", ""), validate=True)
        except ValueError:
            key = b""
        if len(key) != KEY_BYTES:
            raise KeyStoreError(f"The DEDV key file is malformed (key must be {KEY_BYTES} bytes, "
                                f"base64): {self.path}")
        return key

    def create(self) -> bytes:
        """Generate a new key. Refuses if a file is already there."""
        if self.exists():
            raise KeyStoreError(f"Refusing to replace the existing DEDV key file: {self.path}")
        key = AESGCM.generate_key(bit_length=KEY_BYTES * 8)
        body = ("# DEDV DEVELOPMENT KEY - plaintext, NOT production key storage.\n"
                "# Anything encrypted by this app depends on it. Do not commit, share or delete it.\n"
                f"key_id: {KEK_ID}\n"
                "algorithm: AES-256 key-encryption key (wraps per-file keys)\n"
                f"created: {datetime.now().isoformat(timespec='seconds')}\n"
                f"key: {base64.b64encode(key).decode()}\n")
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            _restrict_permissions(self.dir)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # EXCL: never overwrite
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body)
        except FileExistsError:
            raise KeyStoreError(f"Refusing to replace the existing DEDV key file: {self.path}")
        except OSError as e:
            raise KeyStoreError(f"The DEDV key file could not be created ({e.strerror or e}): {self.path}")
        self.permissions_restricted = _restrict_permissions(self.path)
        return key


class KeyManagementService:
    def __init__(self, vault_dir: Path, key_file: DevKeyFile | None = None):
        cfg = Path(vault_dir) / "config"
        self._wrapped = cfg / "wrapped_keys.json"
        self._legacy = cfg / "dev_keys.json"
        self.key_file = key_file or DevKeyFile()
        self._kek: bytes | None = None
        self._lock = threading.RLock()

    # ---- storage helpers ---------------------------------------------------------------------
    def _read(self, path: Path) -> dict:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            raise KeyStoreError(f"The key store could not be read: {path.name} ({e})")
        return data if isinstance(data, dict) else {}

    def _write(self, path: Path, data: dict) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(path)
        except OSError as e:
            raise KeyStoreError(f"The key store could not be written: {e.strerror or e}")

    # ---- KEK ---------------------------------------------------------------------------------
    def _get_kek(self, create_ok: bool) -> bytes:
        if self._kek is not None:
            return self._kek
        if self.key_file.exists():
            self._kek = self.key_file.load()
        elif not create_ok:
            raise KeyStoreError(f"The DEDV key file is missing: {self.key_file.path}. "
                                "Files encrypted with it cannot be opened until it is restored.")
        elif self._read(self._wrapped):
            # Never mint a replacement while records exist that only the lost key could unwrap.
            raise KeyStoreError(f"The DEDV key file is missing: {self.key_file.path}, but this vault "
                                "already holds keys wrapped with it. Restore the file from a backup.")
        else:
            self._kek = self.key_file.create()
        return self._kek

    def check_ready(self) -> None:
        """Raise KeyStoreError if the DEDV key exists but is unusable (so work can stop early)."""
        with self._lock:
            self._get_kek(create_ok=True)

    def key_status(self) -> str:
        """Human-readable state of the development key for the UI (never the key itself)."""
        if not self.key_file.exists():
            return f"not created yet ({self.key_file.path})"
        try:
            self.key_file.load()
            return f"present and valid ({self.key_file.path})"
        except KeyStoreError as e:
            return str(e)

    # ---- per-file secrets ---------------------------------------------------------------------
    def store_secrets(self, key_ref: str, secrets: dict[str, bytes]) -> None:
        with self._lock:
            kek = self._get_kek(create_ok=True)
            nonce = os.urandom(12)
            payload = json.dumps({k: base64.b64encode(v).decode() for k, v in secrets.items()}).encode()
            sealed = AESGCM(kek).encrypt(nonce, payload, key_ref.encode())
            data = self._read(self._wrapped)
            data[key_ref] = {"kek_id": KEK_ID, "nonce": base64.b64encode(nonce).decode(),
                             "ct": base64.b64encode(sealed).decode()}
            self._write(self._wrapped, data)

    def get_secrets(self, key_ref: str) -> dict[str, bytes]:
        with self._lock:
            record = self._read(self._wrapped).get(key_ref)
            if record is None:
                raise KeyStoreError(f"No key found for this file (reference {key_ref}).")
            kek = self._get_kek(create_ok=False)
            try:
                payload = AESGCM(kek).decrypt(base64.b64decode(record["nonce"]),
                                              base64.b64decode(record["ct"]), key_ref.encode())
                return {k: base64.b64decode(v) for k, v in json.loads(payload).items()}
            except (InvalidTag, KeyError, ValueError):
                raise KeyStoreError("The stored key for this file could not be unwrapped. "
                                    "The DEDV key file may not be the one it was created with.")

    def delete(self, key_ref: str) -> None:
        with self._lock:
            data = self._read(self._wrapped)
            if data.pop(key_ref, None) is not None:
                self._write(self._wrapped, data)

    # ---- legacy (plaintext dev_keys.json written before the KEK existed) ----------------------
    def get_legacy_key(self, file_id: str) -> bytes:
        try:
            return base64.b64decode(self._read(self._legacy)[file_id])
        except (KeyError, ValueError):
            raise KeyStoreError("No key found for this file (legacy key store).")

    def delete_legacy_key(self, file_id: str) -> None:
        with self._lock:
            data = self._read(self._legacy)
            if data.pop(file_id, None) is not None:
                self._write(self._legacy, data)
