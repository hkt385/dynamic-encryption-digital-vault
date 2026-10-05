"""Resource/path helpers that work from source and when frozen by PyInstaller."""
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
