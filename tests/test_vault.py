import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg
import pytest

from vault import encryption_service as crypto
from vault.admin import activate_key, rewrap_document
from vault.errors import VaultError
from vault.kek_provider import KekProvider
from vault.key_manager import KeyManager

pytestmark = pytest.mark.integration


def test_round_trip_after_restart(environment, tmp_path):
    original = bytes(range(256)) + b"\x00vault\n"
    source = tmp_path / "input.bin"
    source.write_bytes(original)
    document, grant = environment.upload(source.read_bytes())
    restarted = KeyManager(
        environment.database,
        environment.storage,
        environment.keys,
    )
    result = restarted.decrypt(
        environment.recipient, document, grant.token, uuid4()
    )
    assert result.data == original
    encrypted_path = environment.storage.root / environment.storage.reference(document)
    assert encrypted_path.read_bytes() != original
    events = environment.admin.events(document)
    assert any(row["action"] == "encrypt" and row["result"] == "ok" for row in events)
    assert any(row["action"] == "decrypt" and row["result"] == "ok" for row in events)


def test_distinct_persisted_deks(environment):
    documents = [environment.upload(b"same")[0] for _ in range(2)]
    with environment.database.transaction() as repository:
        rows = [repository.metadata(document) for document in documents]
    deks = [
        crypto.unwrap_dek(
            bytes(row["wrapped_dek"]),
            environment.keys.get_key(row["kek_version"]),
            crypto.key_aad(
                row["document_id"], row["owner_id"],
                row["key_id"], row["kek_version"],
            ),
        )
        for row in rows
    ]
    assert deks[0] != deks[1]
    assert bytes(rows[0]["wrap_nonce"]) != bytes(rows[1]["wrap_nonce"])


@pytest.mark.parametrize("control", ["token_expiry", "policy_expiry", "revoked", "recipient"])
def test_denied_before_unwrap(environment, monkeypatch, control):
    document, grant = environment.upload()
    actor = environment.recipient
    if control == "token_expiry":
        environment.admin.expire_token(grant.token_id)
    elif control == "policy_expiry":
        environment.admin.expire_policy(grant.policy_id)
    elif control == "revoked":
        environment.tokens.revoke(environment.owner, grant.token_id, uuid4())
    else:
        actor = environment.stranger
    original = crypto.unwrap_dek
    calls = []

    def observed(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(crypto, "unwrap_dek", observed)
    with pytest.raises(VaultError, match="ACCESS_DENIED"):
        environment.manager.decrypt(actor, document, grant.token, uuid4())
    assert calls == []


@pytest.mark.parametrize("target", ["ciphertext", "wrapped_key"])
def test_tampering(environment, target):
    document, grant = environment.upload()
    if target == "ciphertext":
        path = environment.storage.root / environment.storage.reference(document)
        value = path.read_bytes()
        path.write_bytes(value[:-1] + bytes([value[-1] ^ 1]))
    else:
        with environment.database.transaction() as repository:
            row = repository.metadata(document)
        value = bytes(row["wrapped_dek"])
        environment.admin.tamper_wrapped_key(
            document, value[:-1] + bytes([value[-1] ^ 1])
        )
    with pytest.raises(VaultError, match="DECRYPTION_FAILED"):
        environment.manager.decrypt(
            environment.recipient, document, grant.token, uuid4()
        )


def test_wrong_document(environment):
    first, grant = environment.upload()
    second, _ = environment.upload()
    assert first != second
    with pytest.raises(VaultError, match="ACCESS_DENIED"):
        environment.manager.decrypt(
            environment.recipient, second, grant.token, uuid4()
        )


def test_non_owner_cannot_revoke(environment):
    document, grant = environment.upload()
    with pytest.raises(VaultError, match="ACCESS_DENIED"):
        environment.tokens.revoke(
            environment.stranger, grant.token_id, uuid4()
        )
    assert environment.manager.decrypt(
        environment.recipient, document, grant.token, uuid4()
    ).data == b"small test file"


def test_nonce_reservations_concurrent(environment):
    with ThreadPoolExecutor(max_workers=8) as executor:
        values = list(executor.map(
            lambda _: environment.database.reserve_nonce(environment.keys.active),
            range(64),
        ))
    assert len(set(values)) == 64


def test_historical_keys_and_rewrap(environment):
    document, grant = environment.upload()
    old_version = environment.keys.active
    new_version = "next-" + uuid4().hex[:20]
    keys = KekProvider(
        {
            old_version: environment.keys.get_key(old_version),
            new_version: secrets.token_bytes(32),
        },
        new_version,
    )
    activate_key(environment.admin_database, keys)
    manager = KeyManager(environment.database, environment.storage, keys)
    # Old document remains readable before rewrapping.
    assert manager.decrypt(
        environment.recipient, document, grant.token, uuid4()
    ).data == b"small test file"
    assert rewrap_document(environment.admin_database, keys, document)
    with environment.database.transaction() as repository:
        row = repository.metadata(document)
    assert row["kek_version"] == new_version
    assert row["current_version"] == 2
    assert manager.decrypt(
        environment.recipient, document, grant.token, uuid4()
    ).data == b"small test file"


def test_audit_failure_prevents_plaintext_return(environment):
    document, grant = environment.upload()
    request_id = uuid4()
    environment.admin.fail_audit_for(request_id)
    try:
        with pytest.raises(VaultError, match="DATABASE_UNAVAILABLE"):
            environment.manager.decrypt(
                environment.recipient, document, grant.token, request_id
            )
    finally:
        environment.admin.clear_audit_failure(request_id)


def test_revocation_waits_for_authorized_read(environment, monkeypatch):
    document, grant = environment.upload()
    entered = threading.Event()
    release = threading.Event()
    original = crypto.unwrap_dek

    def observed(*args, **kwargs):
        entered.set()
        if not release.wait(timeout=5):
            raise RuntimeError("Test synchronization timeout")
        return original(*args, **kwargs)

    monkeypatch.setattr(crypto, "unwrap_dek", observed)
    with ThreadPoolExecutor(max_workers=2) as executor:
        read = executor.submit(
            environment.manager.decrypt,
            environment.recipient, document, grant.token, uuid4(),
        )
        assert entered.wait(timeout=5)
        revoke_started = threading.Event()

        def revoke():
            revoke_started.set()
            environment.tokens.revoke(environment.owner, grant.token_id, uuid4())

        revocation = executor.submit(revoke)
        assert revoke_started.wait(timeout=5)
        release.set()
        assert read.result(timeout=5).data == b"small test file"
        revocation.result(timeout=5)
    with pytest.raises(VaultError, match="ACCESS_DENIED"):
        environment.manager.decrypt(
            environment.recipient, document, grant.token, uuid4()
        )


def test_runtime_cannot_modify_audit_or_reset_nonce(environment):
    with environment.database.transaction() as repository:
        # A legitimate reservation remains available.
        assert repository.reserve_nonce(environment.keys.active) > 0
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with psycopg.connect(environment.app_dsn) as connection:
            connection.execute("DELETE FROM audit_logs")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with psycopg.connect(environment.app_dsn) as connection:
            connection.execute(
                "SELECT setval('kek_wrap_nonce_seq', %s)",
                (1,),
            )
