import base64
import os

import pytest

from conftest import db_bytes, new_vault
from services.key_management_service import KeyStoreError

SECRETS = {"key": os.urandom(32)}
PARAMS = {"wrapped_key": "abc"}


@pytest.fixture
def vault(tmp_path):
    return new_vault(tmp_path / "DEDV")


def store(vault, file_id="f1", algorithm="AES-256-GCM", level="Standard", secrets=SECRETS):
    return vault.keys.store_key(file_id, algorithm, level, secrets, PARAMS, vault.session)


def audit(vault):
    return [(r["action"], r["result"], r["file_id"]) for r in vault.audit.entries()]


def test_token_is_opaque_and_releases_the_record(vault):
    token, other = store(vault), store(vault, "f2")
    assert token != other and len(token) == 22 and "f1" not in token      # 128 random bits, URL-safe
    assert len(base64.urlsafe_b64decode(token + "==")) == 16
    key = vault.keys.release_key(token, "f1", vault.session)
    assert (key.algorithm, key.level, key.secrets, key.params) == ("AES-256-GCM", "Standard", SECRETS, PARAMS)
    assert audit(vault)[-1] == ("key_release", "OK", "f1")


def test_key_material_is_not_stored_in_clear(vault):
    store(vault)
    stored = db_bytes(vault.vault_dir)
    for secret in (SECRETS["key"], vault.session.vmk()):
        assert secret not in stored and base64.b64encode(secret) not in stored
        assert secret.hex().encode() not in stored


def test_release_is_refused_while_locked_and_logged(vault):
    token = store(vault)
    vault.session.lock()
    with pytest.raises(KeyStoreError, match="locked"):
        vault.keys.release_key(token, "f1", vault.session)
    assert audit(vault)[-1] == ("key_release", "DENIED", "f1")
    vault.session.unlock("correct horse battery")
    assert vault.keys.release_key(token, "f1", vault.session).secrets == SECRETS


def test_unknown_token_and_wrong_file_are_refused_and_logged(vault):
    token = store(vault)
    with pytest.raises(KeyStoreError, match="No key is stored"):
        vault.keys.release_key("no-such-token", "f1", vault.session)
    assert audit(vault)[-1] == ("key_release", "DENIED", "f1")
    with pytest.raises(KeyStoreError, match="different file"):       # a valid token, but not this file's
        vault.keys.release_key(token, "f2", vault.session)
    assert audit(vault)[-1] == ("key_release", "DENIED", "f2")


def test_record_swapped_onto_another_file_is_detected(vault):
    """Someone with write access to keys.db points file f2's token at file f1's sealed record."""
    t1, t2 = store(vault, "f1"), store(vault, "f2", secrets={"key": os.urandom(32)})
    with vault.db as conn:
        ct1 = conn.execute("SELECT nonce, ct FROM keys.wrapped_keys WHERE token=?", (t1,)).fetchone()
        conn.execute("UPDATE keys.wrapped_keys SET nonce=?, ct=? WHERE token=?", (ct1["nonce"], ct1["ct"], t2))
    with pytest.raises(KeyStoreError, match="could not be unwrapped"):
        vault.keys.release_key(t2, "f2", vault.session)
    assert audit(vault)[-1] == ("key_release", "DENIED", "f2")
    # Re-labelling a record's owner is caught the same way (file_id is part of the seal).
    with vault.db as conn:
        conn.execute("UPDATE keys.wrapped_keys SET file_id='f2' WHERE token=?", (t1,))
    with pytest.raises(KeyStoreError, match="could not be unwrapped"):
        vault.keys.release_key(t1, "f2", vault.session)


@pytest.mark.parametrize("column,value", [("algorithm", "AES-128-GCM"), ("level", "Low")])
def test_changing_the_recorded_algorithm_or_level_is_detected(vault, column, value):
    token = store(vault)
    with vault.db as conn:
        conn.execute(f"UPDATE keys.wrapped_keys SET {column}=? WHERE token=?", (value, token))
    with pytest.raises(KeyStoreError, match="could not be unwrapped"):
        vault.keys.release_key(token, "f1", vault.session)


def test_record_from_another_vault_cannot_be_unwrapped(vault, tmp_path):
    (tmp_path / "other").mkdir()
    other = new_vault(tmp_path / "other" / "DEDV", "a different password")
    token = store(other)
    with other.db as conn:
        row = tuple(conn.execute("SELECT * FROM keys.wrapped_keys WHERE token=?", (token,)).fetchone())
    with vault.db as conn:
        conn.execute("INSERT INTO keys.wrapped_keys VALUES (?, ?, ?, ?, ?, ?)", row)
    with pytest.raises(KeyStoreError, match="could not be unwrapped"):
        vault.keys.release_key(token, "f1", vault.session)


def test_deleted_record_is_gone(vault):
    token = store(vault)
    vault.keys.delete(token)
    with pytest.raises(KeyStoreError, match="No key is stored"):
        vault.keys.release_key(token, "f1", vault.session)
