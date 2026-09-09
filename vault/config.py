import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from vault.errors import VaultError


@dataclass(frozen=True, repr=False)
class Settings:
    database_url: str
    storage_root: Path
    oidc_issuer: str
    oidc_jwks_url: str
    oidc_audience: str
    docs: bool = False
    allow_http_oidc: bool = False

    @classmethod
    def from_env(cls):
        try:
            settings = cls(
                database_url=os.environ["DATABASE_URL"],
                storage_root=Path(os.getenv("VAULT_ROOT", "./encrypted-files")),
                oidc_issuer=os.environ["OIDC_ISSUER"],
                oidc_jwks_url=os.environ["OIDC_JWKS_URL"],
                oidc_audience=os.environ["OIDC_AUDIENCE"],
                docs=os.getenv("VAULT_DOCS", "0") == "1",
                allow_http_oidc=os.getenv("VAULT_DEV_HTTP_OIDC", "0") == "1",
            )
        except KeyError:
            raise VaultError("INVALID_CONFIGURATION") from None
        settings.validate()
        return settings

    def validate(self):
        for value in (self.oidc_issuer, self.oidc_jwks_url):
            parsed = urlparse(value)
            allowed = {"https"} if not self.allow_http_oidc else {"https", "http"}
            if (
                parsed.scheme not in allowed
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.fragment
            ):
                raise VaultError("INVALID_CONFIGURATION")
        if not self.oidc_audience or not self.database_url:
            raise VaultError("INVALID_CONFIGURATION")
