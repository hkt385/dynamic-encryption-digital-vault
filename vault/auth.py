import threading
import time

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError

from vault.errors import VaultError


class OIDCAuthenticator:
    def __init__(self, settings):
        settings.validate()
        self.settings = settings
        self.jwks = PyJWKClient(
            settings.oidc_jwks_url,
            cache_jwk_set=True,
            lifespan=300,
            timeout=5,
        )

    def verify(self, token: str):
        if not isinstance(token, str) or len(token) > 8192:
            raise VaultError("AUTH_INVALID")
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                raise VaultError("AUTH_INVALID")
            signing_key = self.jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self.settings.oidc_issuer,
                audience=self.settings.oidc_audience,
                leeway=5,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                },
            )
            subject = claims.get("sub")
            scope = claims.get("scope")
            if (
                not isinstance(subject, str)
                or not 1 <= len(subject) <= 255
                or not isinstance(scope, str)
                or "vault" not in scope.split()
            ):
                raise VaultError("AUTH_INVALID")
            return claims["iss"], subject
        except PyJWTError:
            raise VaultError("AUTH_INVALID") from None


class RateLimiter:
    """Single-process token bucket with bounded memory.

    It is an abuse-control layer, not a distributed rate limiter.
    """

    def __init__(self, capacity=60, refill_per_second=1, max_entries=10_000):
        self.capacity = capacity
        self.refill = refill_per_second
        self.max_entries = max_entries
        self._entries = {}
        self._lock = threading.Lock()

    def allow(self, identity, now=None):
        now = time.monotonic() if now is None else now
        with self._lock:
            if identity not in self._entries and len(self._entries) >= self.max_entries:
                self._entries = {
                    key: value
                    for key, value in self._entries.items()
                    if now - value[1] < 600
                }
                if len(self._entries) >= self.max_entries:
                    return False
            balance, last = self._entries.get(identity, (self.capacity, now))
            balance = min(self.capacity, balance + max(0, now - last) * self.refill)
            allowed = balance >= 1
            self._entries[identity] = (balance - 1 if allowed else balance, now)
            return allowed
