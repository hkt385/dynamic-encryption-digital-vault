"""PLACEHOLDER for the existing key-management / KEK system.

TEMPORARY DEV STAND-IN: keys are written unprotected to <vault>/config/dev_keys.json
purely so test uploads stay recoverable. Replace this class with the real system;
nothing here is a KEK design.
"""
import base64
import json
from pathlib import Path


class KeyManagementService:
    def __init__(self, vault_dir: Path):
        self._store = Path(vault_dir) / "config" / "dev_keys.json"

    def _load(self) -> dict:
        try:
            return json.loads(self._store.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def store_key(self, file_id: str, key: bytes) -> None:
        data = self._load()
        data[file_id] = base64.b64encode(key).decode()
        self._store.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_key(self, file_id: str) -> bytes:
        # TODO: access authorization + real key retrieval.
        return base64.b64decode(self._load()[file_id])
