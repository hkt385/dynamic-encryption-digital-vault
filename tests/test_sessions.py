"""Sessions bound to the Windows sign-in (session_service) and the owner-only vault folder."""
import os
import stat

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


# ---- a cache file Windows will not delete -----------------------------------------------------------
@pytest.fixture
def read_only():
    """Marks a file read-only, as a backup or sync tool might: Windows then refuses to delete it."""
    marked = []

    def mark(path):
        os.chmod(path, stat.S_IREAD)
        marked.append(path)
    yield mark
    for path in marked:
        if path.exists():
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def test_lock_still_locks_when_the_cache_file_cannot_be_deleted(vault, read_only):
    from conftest import PASSWORD
    read_only(store(vault).cache_path)
    vault.lock(end_session=True)
    assert not vault.session.is_unlocked
    assert rows(vault) == [] and vault.session.resume() is False    # the file left behind opens nothing
    vault.session.unlock(PASSWORD)
    assert vault.session.is_unlocked


def test_open_asks_for_the_password_when_a_bad_cache_file_cannot_be_deleted(vault, read_only):
    s = store(vault)
    s.cache_path.write_bytes(b"garbage")
    read_only(s.cache_path)
    assert s.resume() is None
    last = last_audit(vault)
    assert (last["action"], last["result"]) == ("session_resume", "DENIED")


def test_password_change_ends_sessions_when_the_cache_file_cannot_be_deleted(vault, read_only):
    from conftest import PASSWORD
    with vault.db as conn:
        conn.execute("INSERT INTO keys.sessions VALUES ('OTHER-PC', 'x', 'y', 'z', x'00', x'00')")
    read_only(store(vault).cache_path)
    vault.session.change_password(PASSWORD, "another long password")
    assert rows(vault) == []


# ---- AuthSession / VaultService ---------------------------------------------------------------------
def test_unlock_starts_a_session_and_reopening_resumes(tmp_path):
    from services.vault_service import VaultService
    v = new_vault(tmp_path / "DEDV")
    vmk = v.session.vmk()
    v.close()
    v2 = VaultService(tmp_path / "DEDV")
    try:
        assert not v2.session.is_unlocked
        assert v2.session.resume() is True
        assert v2.session.vmk() == vmk
    finally:
        v2.close()


def test_lock_keeps_the_session_unless_ended(vault):
    vault.lock()
    assert vault.session.resume() is True
    vault.lock(end_session=True)
    assert not vault.session.is_unlocked
    assert vault.session.resume() is False


def test_password_change_ends_old_sessions_and_starts_a_new_one(vault):
    from conftest import PASSWORD
    old_cache = store(vault).cache_path.read_bytes()
    vault.session.change_password(PASSWORD, "another long password")
    new_cache = store(vault).cache_path.read_bytes()
    store(vault).cache_path.write_bytes(old_cache)
    vault.lock()
    assert vault.session.resume() is False                 # the old session token is dead
    vault.session.unlock("another long password")
    assert store(vault).cache_path.read_bytes() != old_cache != new_cache
    vault.lock()
    assert vault.session.resume() is True


def test_recovery_reset_ends_all_sessions(vault):
    with vault.db as conn:
        conn.execute("INSERT INTO keys.sessions VALUES ('OTHER-PC', 'x', 'y', 'z', x'00', x'00')")
    vault.lock()
    vault.session.reset_with_recovery_key(vault.recovery_key, "another long password")
    assert [r["host"] for r in rows(vault)] == [session_service.host()]


def test_upgrade_of_an_old_vault_starts_a_session(tmp_path):
    from conftest import PASSWORD
    from legacy import write_legacy_vault
    from paths import key_dir
    from services.vault_service import VaultService
    write_legacy_vault(tmp_path / "DEDV", key_dir(), [("a.txt", "Standard", b"aaa")])
    v = VaultService(tmp_path / "DEDV")
    try:
        v.migrate(PASSWORD)
        assert len(rows(v)) == 1
    finally:
        v.close()


def test_unlock_works_when_sessions_are_unavailable(tmp_path, monkeypatch):
    from conftest import PASSWORD
    monkeypatch.setattr(session_service, "available", lambda: False)
    v = new_vault(tmp_path / "DEDV")
    try:
        v.lock()
        v.session.unlock(PASSWORD)
        assert v.session.is_unlocked
        v.lock()
        assert v.session.resume() is False and rows(v) == []
    finally:
        v.close()


def test_audit_order_after_first_password(vault):
    assert [r["action"] for r in vault.audit.entries()][-2:] == ["password_set", "session_start"]


# ---- owner-only vault folder ------------------------------------------------------------------------
@pytest.mark.parametrize("applied", [True, False], ids=["applied", "not-possible"])
def test_vault_folder_permissions_are_restricted_on_open(tmp_path, monkeypatch, applied):
    from services import vault_service
    calls = []
    monkeypatch.setattr(vault_service, "restrict_permissions", lambda p: calls.append(p) or applied)
    v = new_vault(tmp_path / "DEDV")                       # opens even if the folder cannot be restricted
    try:
        assert calls == [v.vault_dir] and v.session.is_unlocked
    finally:
        v.close()


def test_restrict_permissions_leaves_only_the_current_user(tmp_path):
    import subprocess
    from paths import restrict_permissions
    folder = tmp_path / "v"
    folder.mkdir()
    (folder / "inside.txt").write_text("x")
    assert restrict_permissions(folder)
    for p in (folder, folder / "inside.txt"):
        out = subprocess.run(["icacls", str(p)], capture_output=True, text=True).stdout
        assert os.environ["USERNAME"].lower() in out.lower()
        assert r"BUILTIN\Administrators" not in out and r"NT AUTHORITY\SYSTEM" not in out, out
