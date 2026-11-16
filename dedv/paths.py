"""Resource/path helpers that work from source and when frozen by PyInstaller."""
import os
import subprocess
import sys
from pathlib import Path


def app_root() -> Path:
    """Directory containing bundled resources (and the `encryption` folder)."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


def resource_path(*parts: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base.joinpath(*parts)


def encryption_dir() -> Path:
    return app_root() / "encryption"


def model_path() -> Path:
    """model/final_model.joblib: next to the sources in development, bundled data when frozen."""
    return app_root() / "model" / "final_model.joblib"


def docs_dir() -> Path:
    return app_root() / "docs"


def _local_base() -> Path:
    return Path(os.environ.get("LOCALAPPDATA") or Path.home())


def restrict_permissions(path: Path) -> bool:
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


def wipe_and_delete(path: Path) -> None:
    """Overwrite a file with zeros, then delete it. Raises OSError if it cannot be deleted.

    BEST EFFORT, NOT A SECURE WIPE: on SSDs (wear levelling), journaling or copy-on-write file
    systems, and with cloud-sync or backup tools, the old blocks can survive the overwrite.
    """
    path = Path(path)
    try:
        with open(path, "r+b") as f:
            remaining = f.seek(0, os.SEEK_END)
            f.seek(0)
            while remaining > 0:
                n = min(remaining, 1024 * 1024)
                f.write(bytes(n))
                remaining -= n
            f.flush()
            os.fsync(f.fileno())
    except FileNotFoundError:
        return
    except OSError:
        pass                # could not overwrite (read-only, in use): still try to delete
    path.unlink(missing_ok=True)


def key_dir() -> Path:
    """Folder of the DEDV 0.1 plaintext key file (DEDV_key.txt). Only read during the upgrade of
    an old vault; nothing is created there any more.

    Override with the DEDV_KEY_DIR environment variable (used by tests).
    """
    override = os.environ.get("DEDV_KEY_DIR")
    return Path(override) if override else _local_base() / "DEDV" / "keys"


def temp_view_dir() -> Path:
    """Dedicated folder for decrypted copies handed to external applications (outside the vault)."""
    override = os.environ.get("DEDV_TEMP_DIR")
    return Path(override) if override else _local_base() / "DEDV" / "tmp"
