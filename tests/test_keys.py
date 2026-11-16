import base64
import os
import subprocess

import pytest

from paths import key_dir
from services.key_management_service import (KEK_ID, KEY_FILE_NAME, DevKeyFile, KeyManagementService,
                                             KeyStoreError)


def test_key_generated_once_and_reused(tmp_path):
    vault = tmp_path / "vault"
    km = KeyManagementService(vault)
    assert "not created" in km.key_status()
    km.store_secrets("f1", {"key": b"A" * 32})
    path = key_dir() / KEY_FILE_NAME
    first = path.read_text()
    # "restart": new service instance, same folder
    km2 = KeyManagementService(vault)
    assert km2.get_secrets("f1") == {"key": b"A" * 32}
    km2.store_secrets("f2", {"key": b"B" * 32})
    assert path.read_text() == first                      # not regenerated
    assert "present and valid" in km2.key_status()


def test_key_file_format_and_not_literal_name(tmp_path):
    KeyManagementService(tmp_path).store_secrets("f1", {"k": b"x"})
    text = (key_dir() / KEY_FILE_NAME).read_text()
    assert f"key_id: {KEK_ID}" in text
    key = base64.b64decode(next(l for l in text.splitlines() if l.startswith("key:")).split(":", 1)[1].strip())
    assert len(key) == 32 and key != b"DEDV" * 8 and KEK_ID.encode() not in key


def test_secrets_are_not_stored_in_clear(tmp_path):
    km = KeyManagementService(tmp_path)
    secret = os.urandom(32)
    km.store_secrets("f1", {"key": secret})
    stored = (tmp_path / "config" / "wrapped_keys.json").read_text()
    assert base64.b64encode(secret).decode() not in stored and secret.hex() not in stored
    assert str(key_dir()) not in str(tmp_path)           # key file is outside the vault


@pytest.mark.skipif(os.name != "nt", reason="icacls check is Windows specific")
def test_key_file_acl_is_restricted_to_owner(tmp_path):
    km = KeyManagementService(tmp_path)
    km.store_secrets("f1", {"k": b"x"})
    assert km.key_file.permissions_restricted
    out = subprocess.run(["icacls", str(km.key_file.path)], capture_output=True, text=True).stdout
    principals = [l for l in out.splitlines() if ":(" in l]
    assert len(principals) == 1 and os.environ["USERNAME"].lower() in principals[0].lower()


@pytest.mark.parametrize("body", [
    "garbage",
    "key_id: OTHER\nkey: " + base64.b64encode(b"x" * 32).decode(),
    "key_id: DEDV\nkey: " + base64.b64encode(b"short").decode(),
    "key_id: DEDV\nkey: !!!notbase64!!!",
])
def test_malformed_key_is_reported_and_never_replaced(tmp_path, body):
    d = key_dir()
    d.mkdir(parents=True)
    (d / KEY_FILE_NAME).write_text(body)
    km = KeyManagementService(tmp_path)
    with pytest.raises(KeyStoreError, match="malformed"):
        km.store_secrets("f1", {"k": b"x"})
    assert (d / KEY_FILE_NAME).read_text() == body        # untouched


def test_create_refuses_to_overwrite(tmp_path):
    kf = DevKeyFile(tmp_path)
    kf.create()
    with pytest.raises(KeyStoreError, match="Refusing"):
        kf.create()


def test_lost_key_is_not_silently_replaced(tmp_path):
    km = KeyManagementService(tmp_path)
    km.store_secrets("f1", {"k": b"x"})
    (key_dir() / KEY_FILE_NAME).unlink()
    km2 = KeyManagementService(tmp_path)
    with pytest.raises(KeyStoreError, match="missing"):
        km2.get_secrets("f1")
    with pytest.raises(KeyStoreError, match="Restore"):
        km2.store_secrets("f2", {"k": b"y"})
    assert not (key_dir() / KEY_FILE_NAME).exists()


def test_wrong_key_cannot_unwrap(tmp_path):
    KeyManagementService(tmp_path).store_secrets("f1", {"k": b"x"})
    (key_dir() / KEY_FILE_NAME).unlink()
    DevKeyFile().create()                                  # a different DEDV key
    with pytest.raises(KeyStoreError, match="unwrapped"):
        KeyManagementService(tmp_path).get_secrets("f1")


def test_key_dir_is_outside_install_and_vault(tmp_path):
    # default location is under LOCALAPPDATA, never the app/vault
    os.environ.pop("DEDV_KEY_DIR")
    assert "DEDV" in str(key_dir()) and key_dir().name == "keys"
