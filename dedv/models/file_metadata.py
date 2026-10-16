from dataclasses import dataclass, asdict, field
from datetime import datetime
import uuid


@dataclass
class FileMetadata:
    file_id: str
    original_name: str
    file_type: str
    size_bytes: int
    date_added: str          # ISO 8601
    security_level: str
    encrypted_name: str      # physical file inside encrypted_files/ (never shown in the UI)
    predicted_level: str = ""   # raw model prediction (e.g. "High/Critical"); "" for older entries
    algorithm: str = ""         # encryption algorithm id (services.encryption_service); "" = legacy AES-256-GCM
    key_ref: str = ""           # key-store reference of this file's secrets; "" = file_id (legacy)
    enc_params: dict = field(default_factory=dict)   # non-secret parameters (wrapped key, KEM ciphertext)

    @staticmethod
    def new(original_name: str, file_type: str, size_bytes: int,
            security_level: str, encrypted_name: str, file_id: str | None = None,
            predicted_level: str = "", algorithm: str = "", key_ref: str = "",
            enc_params: dict | None = None) -> "FileMetadata":
        return FileMetadata(
            file_id=file_id or uuid.uuid4().hex,
            original_name=original_name,
            file_type=file_type,
            size_bytes=size_bytes,
            date_added=datetime.now().isoformat(timespec="seconds"),
            security_level=security_level,
            encrypted_name=encrypted_name,
            predicted_level=predicted_level,
            algorithm=algorithm,
            key_ref=key_ref,
            enc_params=dict(enc_params or {}),
        )

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "FileMetadata":
        # Fields added after the first release are optional so older vault indexes still load.
        optional = {"predicted_level", "algorithm", "key_ref", "enc_params"}
        kw = {k: d[k] for k in FileMetadata.__dataclass_fields__ if k not in optional}
        kw.update({k: d[k] for k in optional if k in d})
        return FileMetadata(**kw)


def format_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"
