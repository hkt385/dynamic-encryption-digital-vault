"""Resource/path helpers that work from source and when frozen by PyInstaller."""
import os
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


def key_dir() -> Path:
    """Local, non-roaming folder for the DEDV development key (never inside the vault or installer).

    Override with the DEDV_KEY_DIR environment variable (used by tests).
    """
    override = os.environ.get("DEDV_KEY_DIR")
    return Path(override) if override else _local_base() / "DEDV" / "keys"


def temp_view_dir() -> Path:
    """Dedicated folder for decrypted copies handed to external applications (outside the vault)."""
    override = os.environ.get("DEDV_TEMP_DIR")
    return Path(override) if override else _local_base() / "DEDV" / "tmp"
