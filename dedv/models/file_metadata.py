from dataclasses import dataclass, asdict
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

    @staticmethod
    def new(original_name: str, file_type: str, size_bytes: int,
            security_level: str, encrypted_name: str, file_id: str | None = None) -> "FileMetadata":
        return FileMetadata(
            file_id=file_id or uuid.uuid4().hex,
            original_name=original_name,
            file_type=file_type,
            size_bytes=size_bytes,
            date_added=datetime.now().isoformat(timespec="seconds"),
            security_level=security_level,
            encrypted_name=encrypted_name,
        )

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "FileMetadata":
        return FileMetadata(**{k: d[k] for k in FileMetadata.__dataclass_fields__})


def format_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"
