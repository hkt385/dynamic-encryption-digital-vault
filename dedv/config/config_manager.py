"""JSON application configuration. Independent of the UI."""
import json
import os
from pathlib import Path

ACCOUNT_TYPES = ("Personal", "Enterprise")


class ConfigError(Exception):
    pass


def _default_config_path() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home())
    return Path(base) / "DEDV" / "settings.json"


class ConfigManager:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else _default_config_path()
        self.data: dict = {}
        self.was_corrupt = False

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> bool:
        """Returns True if a usable configuration was loaded."""
        self.data, self.was_corrupt = {}, False
        if not self.exists():
            return False
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("not an object")
        except (OSError, ValueError):
            self.was_corrupt = True
            return False
        self.data = data
        return self.is_complete()

    def is_complete(self) -> bool:
        return all(self.data.get(k) for k in
                   ("username", "account_type", "default_directory", "vault_directory"))

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=4), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as e:
            raise ConfigError(f"Could not save settings: {e.strerror or e}") from e

    def get(self, key: str, default=""):
        return self.data.get(key, default)

    def update(self, **values) -> None:
        self.data.update(values)
        self.save()
