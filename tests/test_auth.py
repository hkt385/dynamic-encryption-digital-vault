import pytest

from conftest import PASSWORD, db_bytes, new_vault
from services import auth_service
from services.auth_service import (AuthError, check_password, format_recovery_key, parse_recovery_key,
                                   password_strength)
from services.security_decision_service import FINAL, SecurityDecision
from services.vault_service import OperationError, VaultService

CONTENT = b"secret report\n" * 50


@pytest.fixture
def vault(tmp_path):
    return new_vault(tmp_path / "DEDV")


def stored_file(vault, tmp_path, level="Standard"):
    src = tmp_path / "doc.txt"
    src.write_bytes(CONTENT)
    d = SecurityDecision(FINAL, "Enterprise", predicted=level, level=level)
    assert vault.store_files([(src, d)], "Enterprise").stored == ["doc.txt"]
    return vault.list_files()[-1]


def reopen(vault):
    vault.close()
    return VaultService(vault.vault_dir)


# ---- password rules ----------------------------------------------------------------------------
def test_password_policy_and_strength_hint():
    with pytest.raises(AuthError, match="at least 12"):
        check_password("short pass")
    check_password("twelve chars")
    assert password_strength("abc").startswith("Too short")
    assert password_strength("aaaaaaaaaaaa").startswith("Weak")
    assert password_strength("lowercaseonly").startswith("Weak")
    assert password_strength("Tr1cky-enough!") == "Fair"
    assert password_strength("correct horse battery staple") == "Strong"


def test_new_vault_has_no_password_until_one_is_set(tmp_path):
    vault = VaultService(tmp_path / "DEDV")
    assert not vault.session.is_initialized and not vault.session.is_unlocked
    with pytest.raises(AuthError, match="at least 12"):
        vault.session.initialize("too short")
    assert not vault.session.is_initialized                      # nothing was stored
    vault.session.initialize(PASSWORD)
    assert vault.session.is_initialized and vault.session.is_unlocked
    with pytest.raises(AuthError, match="already has a password"):
        vault.session.initialize("another password!")


def test_argon2id_parameters_and_salt_are_stored_with_the_vault(vault):
    with vault.db as conn:
        row = conn.execute("SELECT * FROM keys.vault_keys WHERE slot='password'").fetchone()
    assert (row["time_cost"], row["memory_kib"], row["parallelism"]) == (
        auth_service.ARGON2_TIME_COST, auth_service.ARGON2_MEMORY_KIB, auth_service.ARGON2_PARALLELISM)
    assert len(row["salt"]) == 16 and len(row["wrapped_vmk"]) == 32 + 16     # VMK + GCM tag
    stored = db_bytes(vault.vault_dir)
    assert PASSWORD.encode() not in stored and vault.session.vmk() not in stored


def test_shipped_argon2id_cost_is_not_the_test_cost():
    """fast_kdf patches the module for the suite; the shipped constants are checked from source."""
    import ast
    from pathlib import Path
    tree = ast.parse(Path(auth_service.__file__).read_text(encoding="utf-8"))
    consts = {n.targets[0].id: eval(compile(ast.Expression(n.value), "", "eval"))
              for n in tree.body if isinstance(n, ast.Assign)
              and isinstance(n.targets[0], ast.Name) and n.targets[0].id.startswith("ARGON2_")}
    assert consts["ARGON2_MEMORY_KIB"] >= 64 * 1024 and consts["ARGON2_TIME_COST"] >= 3
    assert consts["ARGON2_PARALLELISM"] >= 1


# ---- unlock / lock --------------------------------------------------------------------------------
def test_unlock_with_right_and_wrong_password(vault, tmp_path):
    meta = stored_file(vault, tmp_path)
    vault = reopen(vault)
    assert vault.session.is_initialized and not vault.session.is_unlocked
    with pytest.raises(AuthError, match="Wrong password"):
        vault.session.unlock("not the password")
    assert not vault.session.is_unlocked
    with pytest.raises(OperationError, match="locked"):
        vault.read_file(meta.file_id)
    vault.session.unlock(PASSWORD)
    assert vault.read_file(meta.file_id)[1] == CONTENT
    actions = [(r["action"], r["result"]) for r in vault.audit.entries()]
    assert ("unlock", "FAILED") in actions and actions.count(("unlock", "OK")) == 1


def test_lock_zeroes_the_key_and_blocks_every_operation(vault, tmp_path):
    meta = stored_file(vault, tmp_path)
    held = vault.session._vmk
    vault.lock()
    assert held == bytearray(32) and vault.session._vmk is None     # buffer overwritten, reference dropped
    with pytest.raises(AuthError, match="locked"):
        vault.session.vmk()
    with pytest.raises(OperationError, match="locked"):
        vault.read_file(meta.file_id)
    with pytest.raises(OperationError, match="locked"):
        vault.reencrypt(meta.file_id, "High", "Enterprise")
    src = tmp_path / "doc.txt"
    res = vault.store_files([(src, SecurityDecision(FINAL, "Enterprise", predicted="Low", level="Low"))], "Enterprise")
    assert res.stored == [] and "locked" in res.failed[0][1]
    assert len(list(vault.encrypted_dir.iterdir())) == 1            # nothing was written while locked
    vault.lock()                                                    # locking twice logs once
    assert [r["action"] for r in vault.audit.entries()].count("lock") == 1


def test_failed_unlocks_are_delayed_but_never_destroy_anything(vault, tmp_path, monkeypatch):
    meta = stored_file(vault, tmp_path)
    vault.lock()
    now = [1_000_000.0]
    monkeypatch.setattr(auth_service.time, "time", lambda: now[0])
    for _ in range(auth_service.FREE_ATTEMPTS):                     # the first tries are not delayed
        with pytest.raises(AuthError, match="Wrong password") as e:
            vault.session.unlock("wrong wrong wrong")
        assert e.value.retry_after == 0
    with pytest.raises(AuthError, match="Wrong password") as e:     # 4th failure starts a 2 s delay
        vault.session.unlock("wrong wrong wrong")
    assert e.value.retry_after == pytest.approx(2)
    with pytest.raises(AuthError, match="Try again in") as e:       # even the RIGHT password must wait
        vault.session.unlock(PASSWORD)
    assert not vault.session.is_unlocked
    now[0] += 2.1
    with pytest.raises(AuthError, match="Wrong password") as e:     # 5th failure: 4 s
        vault.session.unlock("wrong wrong wrong")
    assert e.value.retry_after == pytest.approx(4)
    vault = reopen(vault)                                           # restarting the app does not reset it
    assert vault.session.retry_after() == pytest.approx(4)
    now[0] += 4.1
    vault.session.unlock(PASSWORD)
    assert vault.session.retry_after() == 0 and vault.read_file(meta.file_id)[1] == CONTENT


def test_delay_is_capped(vault, monkeypatch):
    vault.lock()
    now = [1_000_000.0]
    monkeypatch.setattr(auth_service.time, "time", lambda: now[0])
    for _ in range(40):
        with pytest.raises(AuthError):
            vault.session.unlock("wrong wrong wrong")
        now[0] += auth_service.MAX_DELAY_SECONDS + 1
    now[0] -= auth_service.MAX_DELAY_SECONDS + 1
    assert vault.session.retry_after() == pytest.approx(auth_service.MAX_DELAY_SECONDS)


# ---- password change and recovery ------------------------------------------------------------------
def test_password_change_rewraps_only_the_master_key(vault, tmp_path):
    meta = stored_file(vault, tmp_path)
    enc = vault.encrypted_dir / meta.encrypted_name
    with vault.db as conn:
        before = conn.execute("SELECT nonce, ct FROM keys.wrapped_keys").fetchall()
    ciphertext = enc.read_bytes()
    with pytest.raises(AuthError, match="Wrong password"):
        vault.session.change_password("not the password", "a brand new password")
    with pytest.raises(AuthError, match="at least 12"):
        vault.session.change_password(PASSWORD, "short")
    vault.session.change_password(PASSWORD, "a brand new password")
    with vault.db as conn:
        assert conn.execute("SELECT nonce, ct FROM keys.wrapped_keys").fetchall() == before   # files untouched
    assert enc.read_bytes() == ciphertext
    vault = reopen(vault)
    with pytest.raises(AuthError, match="Wrong password"):
        vault.session.unlock(PASSWORD)                              # the old password is dead
    vault.session.unlock("a brand new password")
    assert vault.read_file(meta.file_id)[1] == CONTENT              # old files still decrypt
    assert "password_change" in [r["action"] for r in vault.audit.entries()]


def test_recovery_key_format():
    raw = bytes(range(32))
    text = format_recovery_key(raw)
    groups = text.split("-")
    assert len(groups) == 13 and all(len(g) == 4 for g in groups)
    assert parse_recovery_key(text) == raw
    assert parse_recovery_key(text.lower().replace("-", " ")) == raw     # typed back loosely
    for bad in ("", "AAAA-BBBB", text[:-1] + "1", "!!!!"):
        with pytest.raises(AuthError, match="not a valid recovery key"):
            parse_recovery_key(bad)


def test_recovery_key_resets_a_forgotten_password(vault, tmp_path):
    meta = stored_file(vault, tmp_path)
    recovery = vault.recovery_key
    assert recovery.encode() not in db_bytes(vault.vault_dir)       # shown once, never stored
    vault = reopen(vault)
    wrong = format_recovery_key(bytes(32))
    with pytest.raises(AuthError, match="does not belong"):
        vault.session.reset_with_recovery_key(wrong, "the next password!")
    with pytest.raises(AuthError, match="at least 12"):
        vault.session.reset_with_recovery_key(recovery, "short")
    assert not vault.session.is_unlocked
    vault.session.reset_with_recovery_key(recovery, "the next password!")
    assert vault.session.is_unlocked and vault.read_file(meta.file_id)[1] == CONTENT
    vault = reopen(vault)
    with pytest.raises(AuthError, match="Wrong password"):
        vault.session.unlock(PASSWORD)
    vault.session.unlock("the next password!")
    assert vault.read_file(meta.file_id)[1] == CONTENT
    actions = [(r["action"], r["result"]) for r in vault.audit.entries()]
    assert ("recovery_use", "FAILED") in actions and ("recovery_use", "OK") in actions
    vault.lock()                                                    # the recovery key still works afterwards
    vault.session.reset_with_recovery_key(recovery, "yet another password")
    assert vault.session.is_unlocked


def test_recovery_reset_clears_the_failed_attempt_delay(vault, monkeypatch):
    vault.lock()
    now = [1_000_000.0]
    monkeypatch.setattr(auth_service.time, "time", lambda: now[0])
    for _ in range(auth_service.FREE_ATTEMPTS + 3):
        with pytest.raises(AuthError, match="Wrong password"):
            vault.session.unlock("wrong wrong wrong")
        now[0] += 1000
    now[0] -= 1000
    assert vault.session.retry_after() > 0
    vault.session.reset_with_recovery_key(vault.recovery_key, "the next password!")
    assert vault.session.retry_after() == 0
