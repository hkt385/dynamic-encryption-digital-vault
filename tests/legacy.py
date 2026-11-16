"""Test helper: writes a vault in the DEDV 0.1 on-disk format (JSON index, JSON key stores and the
plaintext DEDV_key.txt), without using the application's storage or key code, so migration tests
keep describing the OLD format no matter how the application changes.

Format (checked against the 0.1 code, git tag/branch `main` at 053328d):
  metadata/files.json        list of metadata dicts
  config/wrapped_keys.json   {key_ref: {"kek_id": "DEDV", "nonce": b64, "ct": b64}}
                             ct = AES-256-GCM(KEK, nonce, json({name: b64(secret)}), aad=key_ref)
  config/dev_keys.json       {file_id: b64(AES-256 key)}   (entries older than algorithm ids)
  <key dir>/DEDV_key.txt     "key_id: DEDV" / "key: <b64 of 32 bytes>"
"""
import base64
import json
import os
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services.encryption_service import EncryptionService


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def write_key_file(key_dir: Path) -> bytes:
    kek = os.urandom(32)
    key_dir = Path(key_dir)
    key_dir.mkdir(parents=True, exist_ok=True)
    (key_dir / "DEDV_key.txt").write_text(
        "# DEDV DEVELOPMENT KEY - plaintext, NOT production key storage.\n"
        f"key_id: DEDV\nalgorithm: AES-256 key-encryption key (wraps per-file keys)\n"
        f"created: 2026-01-01T00:00:00\nkey: {_b64(kek)}\n", encoding="utf-8")
    return kek


def write_legacy_vault(vault_dir: Path, key_dir: Path, entries) -> list[dict]:
    """entries: (name, level, content) tuples. level None = entry from before algorithm ids
    (AES-256-GCM, plaintext key in dev_keys.json). Returns the metadata dicts written."""
    vault_dir = Path(vault_dir)
    for sub in ("encrypted_files", "metadata", "config"):
        (vault_dir / sub).mkdir(parents=True, exist_ok=True)
    kek = write_key_file(key_dir)
    enc = EncryptionService()
    index, wrapped, plain = [], {}, {}
    for name, level, content in entries:
        file_id = uuid.uuid4().hex
        meta = {"file_id": file_id, "original_name": name,
                "file_type": (Path(name).suffix.lstrip(".") or "file").upper(),
                "size_bytes": len(content), "date_added": "2026-01-01T00:00:00",
                "security_level": level or "Standard", "encrypted_name": f"{file_id}.enc"}
        result = enc.encrypt_data(content, vault_dir / "encrypted_files" / meta["encrypted_name"],
                                  level or "Standard")
        if level is None:
            plain[file_id] = _b64(result.secrets["key"])
        else:
            meta.update(predicted_level=level if level in ("Low", "Standard", "Enhanced") else "High/Critical",
                        algorithm=result.algorithm, key_ref=file_id, enc_params=result.params)
            nonce = os.urandom(12)
            payload = json.dumps({k: _b64(v) for k, v in result.secrets.items()}).encode()
            wrapped[file_id] = {"kek_id": "DEDV", "nonce": _b64(nonce),
                                "ct": _b64(AESGCM(kek).encrypt(nonce, payload, file_id.encode()))}
        index.append(meta)
    (vault_dir / "metadata" / "files.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    if wrapped:
        (vault_dir / "config" / "wrapped_keys.json").write_text(json.dumps(wrapped, indent=2), encoding="utf-8")
    if plain:
        (vault_dir / "config" / "dev_keys.json").write_text(json.dumps(plain, indent=2), encoding="utf-8")
    return index
