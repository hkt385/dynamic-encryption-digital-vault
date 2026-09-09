import base64
import binascii
import hashlib
import json
import os
import re
import secrets

import keyring

from vault.errors import VaultError

VERSION_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
KEYRING_SERVICE = "dynamic-vault"


def require_os_keyring():
    backend = keyring.get_keyring()
    module = type(backend).__module__
    approved = (
        "keyring.backends.SecretService",
        "keyring.backends.macOS",
        "keyring.backends.Windows",
    )
    if not module.startswith(approved):
        raise VaultError("UNSUPPORTED_KEYRING")
    # Intentionally reject plaintext and generic fallback backends.
    return backend


class KekProvider:
    def __init__(self, keys: dict[str, bytes], active: str):
        if not keys or active not in keys:
            raise VaultError("INVALID_CONFIGURATION")
        if any(
            not VERSION_PATTERN.fullmatch(version)
            or not isinstance(key, bytes)
            or len(key) != 32
            for version, key in keys.items()
        ):
            raise VaultError("INVALID_CONFIGURATION")
        fingerprints = [hashlib.sha256(key).digest() for key in keys.values()]
        if len(set(fingerprints)) != len(fingerprints):
            raise VaultError("DUPLICATE_KEK")
        self._keys = dict(keys)
        self.active = active

    @classmethod
    def from_env(cls):
        try:
            active = os.environ["VAULT_ACTIVE_KEK"]
            source = os.getenv("VAULT_KEK_SOURCE", "keyring")
            if source == "env":
                encoded = json.loads(os.environ["VAULT_KEKS_JSON"])
                if not isinstance(encoded, dict):
                    raise ValueError()
            elif source == "keyring":
                backend = require_os_keyring()
                versions = os.environ["VAULT_KEK_VERSIONS"].split(",")
                encoded = {
                    version: backend.get_password(KEYRING_SERVICE, version)
                    for version in versions
                }
            else:
                raise ValueError()
            keys = {
                version: base64.b64decode(value, validate=True)
                for version, value in encoded.items()
            }
            return cls(keys, active)
        except (KeyError, TypeError, ValueError, binascii.Error):
            raise VaultError("INVALID_CONFIGURATION") from None

    def get_key(self, version: str) -> bytes:
        try:
            return self._keys[version]
        except KeyError:
            raise VaultError("KEY_UNAVAILABLE") from None

    def fingerprints(self) -> dict[str, bytes]:
        return {
            version: hashlib.sha256(key).digest()
            for version, key in self._keys.items()
        }


def create_keyring_key(version: str):
    if not VERSION_PATTERN.fullmatch(version):
        raise VaultError("INVALID_CONFIGURATION")
    backend = require_os_keyring()
    if backend.get_password(KEYRING_SERVICE, version) is not None:
        raise VaultError("KEY_ALREADY_EXISTS")
    encoded = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    backend.set_password(KEYRING_SERVICE, version, encoded)
