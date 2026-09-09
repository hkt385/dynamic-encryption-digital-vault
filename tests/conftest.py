import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.db_admin import TestAdmin
from vault.admin import activate_key
from vault.config import Settings
from vault.db import AdminDatabase, Database
from vault.kek_provider import KekProvider
from vault.key_manager import KeyManager
from vault.storage import EncryptedStorage
from vault.token_service import TokenService


@dataclass(repr=False)
class Environment:
    database: Database
    admin_database: AdminDatabase
    admin: TestAdmin
    manager: KeyManager
    storage: EncryptedStorage
    tokens: TokenService
    keys: KekProvider
    owner: object
    recipient: object
    stranger: object
    app_dsn: str

    def upload(self, payload=b"small test file"):
        document = self.manager.encrypt(
            self.owner, "example.bin", payload, uuid4()
        )
        with self.database.transaction() as repository:
            expiry = repository.now() + timedelta(hours=1)
        grant = self.tokens.grant(
            self.owner, document, self.recipient, expiry, uuid4()
        )
        return document, grant


@pytest.fixture
def environment(tmp_path):
    app_dsn = os.environ.get("TEST_DATABASE_URL")
    admin_dsn = os.environ.get("TEST_ADMIN_DATABASE_URL")
    if not app_dsn or not admin_dsn:
        pytest.fail("Configure both PostgreSQL test connection URLs")
    database = Database(app_dsn)
    admin_database = AdminDatabase(admin_dsn)
    version = "test-" + uuid4().hex[:20]
    keys = KekProvider({version: secrets.token_bytes(32)}, version)
    activate_key(admin_database, keys)
    with database.transaction() as repository:
        issuer = "https://tests.example/" + uuid4().hex
        owner = repository.provision_user(issuer, "owner")
        recipient = repository.provision_user(issuer, "recipient")
        stranger = repository.provision_user(issuer, "stranger")
    storage = EncryptedStorage(tmp_path / "encrypted")
    manager = KeyManager(database, storage, keys)
    return Environment(
        database, admin_database, TestAdmin(admin_dsn),
        manager, storage, TokenService(database), keys,
        owner, recipient, stranger, app_dsn,
    )


@pytest.fixture
def oidc_server():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
    jwks = json.dumps({"keys": [public_jwk]}).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(jwks)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    issuer = f"http://127.0.0.1:{server.server_port}"

    def issue(subject, **overrides):
        now = int(time.time())
        claims = {
            "iss": issuer,
            "sub": subject,
            "aud": "vault-test-api",
            "scope": "vault",
            "iat": now,
            "exp": now + 300,
        }
        claims.update(overrides)
        return jwt.encode(
            claims,
            private_key,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )

    yield issuer, issue
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture
def api_settings(environment, oidc_server):
    issuer, _ = oidc_server
    return Settings(
        database_url=environment.app_dsn,
        storage_root=environment.storage.root,
        oidc_issuer=issuer,
        oidc_jwks_url=issuer + "/jwks",
        oidc_audience="vault-test-api",
        allow_http_oidc=True,
    )
