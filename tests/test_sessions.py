"""Sessions bound to the Windows sign-in (session_service) and the owner-only vault folder."""
import os

import pytest

from conftest import db_bytes, new_vault
from services import session_service
from services.session_service import SessionStore

pytestmark = pytest.mark.skipif(os.name != "nt", reason="sessions use Windows sign-in APIs")


def store(vault) -> SessionStore:
    return SessionStore(vault.db, vault.audit, vault.vault_dir)


def rows(vault):
    with vault.db as conn:
        return conn.execute("SELECT * FROM keys.sessions").fetchall()


def last_audit(vault):
    return vault.audit.entries()[-1]


@pytest.fixture
def vault(tmp_path):
    v = new_vault(tmp_path / "DEDV")
    yield v
    v.close()


# ---- session store ----------------------------------------------------------------------------------
def test_start_then_resume_returns_the_vmk(vault):
    s, vmk = store(vault), vault.session.vmk()
    s.start(vmk)
    assert s.resume() == vmk
    assert len(s.cache_path.read_bytes()) == 48
    assert [r["host"] for r in rows(vault)] == [session_service.host()]


def test_end_removes_row_and_cache(vault):
    s = store(vault)
    s.start(vault.session.vmk())
    s.end("lock")
    assert s.resume() is None
    assert not s.cache_path.exists() and rows(vault) == []
    end = [r for r in vault.audit.entries() if r["action"] == "session_end"][-1]
    assert end["detail"] == "lock"


def test_other_sign_in_is_refused(vault, monkeypatch):
    s = store(vault)
    s.start(vault.session.vmk())
    monkeypatch.setattr(session_service, "logon_id", lambda: "ffffffff00000000")
    assert s.resume() is None
    assert not s.cache_path.exists()
    last = last_audit(vault)
    assert (last["action"], last["result"], last["detail"]) == ("session_resume", "DENIED", "other sign-in")


def test_restart_is_refused(vault, monkeypatch):
    s = store(vault)
    s.start(vault.session.vmk())
    monkeypatch.setattr(session_service, "unprotect", lambda data: bytes(len(data)))  # new boot key
    assert s.resume() is None
    last = last_audit(vault)
    assert (last["action"], last["result"], last["detail"]) == ("session_resume", "DENIED", "restarted or altered")


def test_altered_row_is_refused(vault):
    s = store(vault)
    s.start(vault.session.vmk())
    with vault.db as conn:
        wrapped = bytearray(conn.execute("SELECT wrapped_vmk FROM keys.sessions").fetchone()[0])
        wrapped[-1] ^= 1
        conn.execute("UPDATE keys.sessions SET wrapped_vmk=?", (bytes(wrapped),))
    assert s.resume() is None


@pytest.mark.parametrize("content", [b"", bytes(47), os.urandom(48)], ids=["empty", "short", "random"])
def test_bad_cache_file_is_refused(vault, content):
    s = store(vault)
    s.start(vault.session.vmk())
    s.cache_path.write_bytes(content)
    assert s.resume() is None
    assert not s.cache_path.exists()


def test_no_cache_file_is_silent(tmp_path):
    vault = new_vault(tmp_path / "DEDV")
    try:
        s = store(vault)
        s.cache_path.unlink(missing_ok=True)
        assert s.resume() is None
        assert "session_resume" not in [r["action"] for r in vault.audit.entries()]
    finally:
        vault.close()


def test_sessions_do_not_cross_vaults(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a, b = new_vault(tmp_path / "a" / "DEDV"), new_vault(tmp_path / "b" / "DEDV")
    try:
        sa, sb = store(a), store(b)
        sb.end("lock")
        sa.start(a.session.vmk())
        assert sa.cache_path != sb.cache_path
        assert sb.resume() is None
    finally:
        a.close()
        b.close()


def test_end_all_removes_every_row(vault):
    s = store(vault)
    s.start(vault.session.vmk())
    with vault.db as conn:
        conn.execute("INSERT INTO keys.sessions VALUES ('OTHER-PC', 'x', 'y', 'z', x'00', x'00')")
    s.end_all("password change")
    assert rows(vault) == [] and not s.cache_path.exists()


def test_no_secret_in_clear(vault):
    s, vmk = store(vault), vault.session.vmk()
    s.start(vmk)
    cache = s.cache_path.read_bytes()
    session_key = session_service.unprotect(cache[16:])
    on_disk = db_bytes(vault.vault_dir)
    assert vmk not in on_disk and vmk not in cache
    assert session_key not in on_disk and session_key not in cache


def test_schema_step_2(vault):
    with vault.db as conn:
        assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 2
