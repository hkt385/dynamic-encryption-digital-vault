from dataclasses import dataclass, field
from datetime import datetime
import uuid


@dataclass
class FileMetadata:
    """One row of the files table in <vault>/metadata/vault.db. Holds no key material.
    The decision (inputs, prediction, confidence, final level, override) is recorded at
    `date_added`; later level changes are timestamped in the audit log."""
    file_id: str
    original_name: str
    file_type: str
    size_bytes: int
    date_added: str          # ISO 8601, local time
    security_level: str      # final level, the one the file is encrypted at
    encrypted_name: str      # physical file inside encrypted_files/ (never shown in the UI)
    predicted_level: str = ""   # raw model prediction (e.g. "High/Critical"); "" if none was recorded
    algorithm: str = ""         # encryption algorithm id (services.encryption_service)
    token: str = ""             # opaque reference to this file's key record in keys.db
    confidence: float | None = None    # model confidence; None if not recorded (upgraded 0.1 files)
    override: bool = False             # final level differs from a single-level prediction
    model_inputs: dict = field(default_factory=dict)   # the 7 parameters the prediction used

    @staticmethod
    def new(original_name: str, file_type: str, size_bytes: int,
            security_level: str, encrypted_name: str, file_id: str | None = None,
            predicted_level: str = "", algorithm: str = "", token: str = "",
            confidence: float | None = None, override: bool = False,
            model_inputs: dict | None = None) -> "FileMetadata":
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
            token=token,
            confidence=confidence,
            override=override,
            model_inputs=dict(model_inputs or {}),
        )


def format_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"
