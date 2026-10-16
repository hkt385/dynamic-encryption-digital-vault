"""Deciding how a decrypted file may be shown, and managing temporary plaintext copies.

Preferred path is in-memory preview (text / image / PDF) - no plaintext touches the disk.
Only files handed to an external application are written to disk, into a dedicated folder
(paths.temp_view_dir(), outside the vault) under a unique random directory.

Cleanup limits (documented in docs/DEVELOPER_INSTRUCTIONS.md): the app cannot know when an
external program is done with a file, so copies are deleted when the app exits and any that were
still locked are removed by the sweep at the next start. Plaintext is deleted, not securely
wiped (not possible to guarantee on SSDs / journaling filesystems).
"""
import os
import re
import shutil
import uuid
from pathlib import Path

from paths import temp_view_dir

TEXT_EXT = {".txt", ".md", ".log", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg",
            ".conf", ".toml", ".html", ".htm", ".css", ".py", ".js", ".ts", ".java", ".c", ".h",
            ".cpp", ".cs", ".go", ".rs", ".sql", ".sh", ".bat", ".cmd", ".ps1", ".vbs", ".rtf"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico"}
PDF_EXT = {".pdf"}
# Never launched, not even after confirmation.
BLOCKED_EXT = {".exe", ".dll", ".msi", ".scr", ".com", ".pif", ".lnk", ".jar", ".reg", ".msc",
               ".cpl", ".hta", ".wsf", ".appx", ".msix", ".application", ".gadget", ".apk"}

TEXT, IMAGE, PDF, BLOCKED, EXTERNAL = "text", "image", "pdf", "blocked", "external"
MAX_TEXT_BYTES = 2 * 1024 * 1024


def classify(name: str) -> str:
    ext = Path(name).suffix.lower()
    if ext in BLOCKED_EXT:
        return BLOCKED
    if ext in TEXT_EXT:
        return TEXT
    if ext in IMAGE_EXT:
        return IMAGE
    if ext in PDF_EXT:
        return PDF
    return EXTERNAL       # unknown: needs explicit user confirmation before opening externally


def _safe_name(name: str) -> str:
    base = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", Path(name).name).strip(" .") or "file"
    return base[:120]


class TempFiles:
    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root else temp_view_dir()
        self._dirs: list[Path] = []

    def write(self, name: str, data: bytes) -> Path:
        """Write a decrypted copy to <root>/<random>/<name>; owner-only where supported."""
        d = self.root / uuid.uuid4().hex
        d.mkdir(parents=True, exist_ok=False)
        self._dirs.append(d)
        path = d / _safe_name(name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        if os.name != "nt":
            os.chmod(d, 0o700)
        else:
            from services.key_management_service import _restrict_permissions
            _restrict_permissions(d)
        return path

    def cleanup(self) -> list[Path]:
        """Delete tracked copies. Returns the ones that could not be removed (still in use)."""
        left = []
        for d in self._dirs:
            try:
                shutil.rmtree(d)
            except FileNotFoundError:
                pass
            except OSError:
                left.append(d)
        self._dirs = left
        return left

    def sweep_stale(self) -> int:
        """Remove leftovers from earlier runs (call at startup). Returns how many were removed."""
        removed = 0
        if self.root.is_dir():
            for d in self.root.iterdir():
                try:
                    shutil.rmtree(d)
                    removed += 1
                except OSError:
                    pass            # in use by another process; next start will retry
        return removed
