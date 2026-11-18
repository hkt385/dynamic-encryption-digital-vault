"""UI flows for the vault password: unlock, first password, upgrade, lock button and auto-lock."""
from pathlib import Path

import pytest
from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from config.config_manager import ConfigManager
from conftest import PASSWORD, new_vault, wait_until
from legacy import write_legacy_vault
from paths import key_dir
from services import auth_service
from services.storage_service import VaultLock
from services.vault_service import VaultService
from ui import unlock_dialog
from ui.developer_page import DeveloperPage
from ui.main_window import MainWindow
from ui.unlock_dialog import NewPasswordDialog, RecoveryKeyDialog, UnlockDialog, open_vault

NEW_PASSWORD = "a brand new password"


def closed_without_session(vault_dir):
    """An existing vault, closed with its Windows sign-in session ended (so it asks again)."""
    vault = new_vault(vault_dir)
    vault.lock(end_session=True)
    vault.close()


def lock_held(tmp_path) -> bool:
    """Is a vault under this test's folder still locked by this process?"""
    return any(Path(p).is_relative_to(tmp_path.resolve()) for p in VaultLock._held)


@pytest.fixture(autouse=True)
def boxes(monkeypatch):
    """Record message boxes instead of blocking on them. Questions are answered from `answers`
    (a list consumed in order; default No)."""
    shown, answers = [], []
    for name in ("information", "warning", "critical"):
        monkeypatch.setattr(QMessageBox, name, staticmethod(lambda *a, _n=name: shown.append((_n, a[2])) or 0))

    def question(parent, title, text, *a, **k):
        shown.append(("question", text))
        return answers.pop(0) if answers else QMessageBox.No
    monkeypatch.setattr(QMessageBox, "question", staticmethod(question))
    return _Boxes(shown, answers)


class _Boxes:
    def __init__(self, shown, answers):
        self.shown, self.answers = shown, answers

    def text(self):
        return "\n".join(t for _, t in self.shown)


@pytest.fixture
def typed(monkeypatch):
    """Stand in for the user at the password dialogs: NewPasswordDialog is 'filled in' with these
    values and accepted (or cancelled if password is None); the recovery key dialog records the key."""
    state = {"password": NEW_PASSWORD, "first": "", "recovery_keys": []}

    def new_password_exec(self):
        if state["password"] is None:
            return QDialog.Rejected
        self.password, self.first_value = state["password"], state["first"]
        return QDialog.Accepted

    def recovery_exec(self):
        state["recovery_keys"].append(self.key.text())
        return QDialog.Accepted
    monkeypatch.setattr(NewPasswordDialog, "exec", new_password_exec)
    monkeypatch.setattr(RecoveryKeyDialog, "exec", recovery_exec)
    return state


def config_for(tmp_path, **extra):
    cfg = ConfigManager(tmp_path / "settings.json")
    cfg.update(username="u", account_type="Enterprise", default_directory=str(tmp_path),
               vault_directory=str(tmp_path / "DEDV"), **extra)
    return cfg


# ---- dialogs ---------------------------------------------------------------------------------------
def test_new_password_dialog_validates_before_accepting(qapp):
    dlg = NewPasswordDialog("Create", "intro", "Current password")
    dlg.new.setText("short")
    assert "Too short" in dlg.hint.text()
    dlg._finish()
    assert "at least 12" in dlg.error.text() and dlg.result() != QDialog.Accepted
    dlg.new.setText(NEW_PASSWORD)
    dlg.confirm.setText("something else!!")
    dlg._finish()
    assert "not the same" in dlg.error.text() and dlg.result() != QDialog.Accepted
    dlg.confirm.setText(NEW_PASSWORD)
    dlg._finish()
    assert "required" in dlg.error.text()                       # the current password is missing
    dlg.first.setText(PASSWORD)
    dlg._finish()
    assert dlg.result() == QDialog.Accepted and (dlg.password, dlg.first_value) == (NEW_PASSWORD, PASSWORD)
    assert dlg.new.echoMode() == dlg.new.EchoMode.Password and dlg.first.echoMode() == dlg.new.EchoMode.Password


def test_recovery_key_dialog_cannot_be_dismissed_until_confirmed(qapp):
    dlg = RecoveryKeyDialog("AAAA-BBBB-CCCC")
    dlg.show()
    assert dlg.key.text() == "AAAA-BBBB-CCCC" and dlg.key.isReadOnly() and not dlg.done_btn.isEnabled()
    dlg.reject()                                                # Esc / close button
    assert dlg.isVisible()
    dlg.saved.setChecked(True)
    assert dlg.done_btn.isEnabled()
    dlg.done_btn.click()
    assert not dlg.isVisible() and dlg.result() == QDialog.Accepted


def test_unlock_dialog_wrong_then_right_password(qapp, tmp_path):
    vault = new_vault(tmp_path / "DEDV")
    vault.lock()
    dlg = UnlockDialog(vault.session, str(vault.vault_dir))
    dlg.password.setText("not the password")
    dlg.try_unlock()
    assert "Wrong password" in dlg.message.text() and dlg.password.text() == ""
    assert dlg.result() != QDialog.Accepted and not vault.session.is_unlocked
    dlg.password.setText(PASSWORD)
    dlg.unlock_btn.click()
    assert dlg.result() == QDialog.Accepted and vault.session.is_unlocked
    assert QApplication.overrideCursor() is None                # busy cursor restored


def test_unlock_dialog_shows_the_delay_and_disables_unlock(qapp, tmp_path, monkeypatch):
    vault = new_vault(tmp_path / "DEDV")
    vault.lock()
    now = [1_000_000.0]
    monkeypatch.setattr(auth_service.time, "time", lambda: now[0])
    dlg = UnlockDialog(vault.session)
    for _ in range(auth_service.FREE_ATTEMPTS + 1):
        dlg.password.setText("not the password")
        dlg.try_unlock()
    assert not dlg.unlock_btn.isEnabled() and "Try again in" in dlg.message.text()
    dlg.password.setText(PASSWORD)
    dlg.try_unlock()                                            # ignored while the delay runs
    assert not vault.session.is_unlocked
    assert not UnlockDialog(vault.session).unlock_btn.isEnabled()      # reopening the dialog does not help
    now[0] += 3
    dlg._tick()
    assert dlg.unlock_btn.isEnabled() and dlg.message.text() == ""
    dlg.password.setText(PASSWORD)
    dlg.try_unlock()
    assert vault.session.is_unlocked


def test_unlock_dialog_reset_with_recovery_key(qapp, tmp_path, typed, boxes):
    vault = new_vault(tmp_path / "DEDV")
    vault.lock()
    dlg = UnlockDialog(vault.session)
    typed["first"] = "AAAA-BBBB"
    dlg.reset_btn.click()
    assert "not a valid recovery key" in dlg.message.text() and not vault.session.is_unlocked
    typed["first"] = vault.recovery_key
    dlg.reset_btn.click()
    assert dlg.result() == QDialog.Accepted and vault.session.is_unlocked
    vault.lock()
    vault.session.unlock(NEW_PASSWORD)


# ---- open_vault: the three start-up paths ------------------------------------------------------------
def test_first_run_creates_password_and_shows_recovery_key_once(qapp, tmp_path, typed):
    vault = open_vault(tmp_path / "DEDV")
    assert vault.session.is_unlocked and len(typed["recovery_keys"]) == 1
    vault.close()
    reopened = VaultService(tmp_path / "DEDV")
    reopened.session.reset_with_recovery_key(typed["recovery_keys"][0], "yet another password")   # the key shown works
    reopened.close()


def test_cancelling_at_start_up_opens_nothing_and_releases_the_lock(qapp, tmp_path, typed, monkeypatch):
    typed["password"] = None
    assert open_vault(tmp_path / "DEDV") is None                # first-password dialog cancelled
    assert not lock_held(tmp_path)
    closed_without_session(tmp_path / "DEDV")
    monkeypatch.setattr(UnlockDialog, "exec", lambda self: QDialog.Rejected)
    assert open_vault(tmp_path / "DEDV") is None                # unlock dialog closed
    assert not lock_held(tmp_path)


def test_existing_vault_asks_for_the_password(qapp, tmp_path, monkeypatch):
    closed_without_session(tmp_path / "DEDV")

    def fill(self):
        self.password.setText(PASSWORD)
        self.try_unlock()
        return self.result()
    monkeypatch.setattr(UnlockDialog, "exec", fill)
    vault = open_vault(tmp_path / "DEDV")
    assert vault.session.is_unlocked
    vault.close()


def _legacy(tmp_path):
    return write_legacy_vault(tmp_path / "DEDV", key_dir(),
                              [("a.txt", "Standard", b"aaa"), ("b.txt", "High", b"bbb"), ("c.txt", None, b"ccc")])


@pytest.mark.parametrize("delete_key_file", [False, True])
def test_old_vault_is_upgraded_and_the_key_file_is_deleted_only_on_yes(qapp, tmp_path, typed, boxes, delete_key_file):
    _legacy(tmp_path)
    key_file = key_dir() / "DEDV_key.txt"
    boxes.answers.append(QMessageBox.Yes if delete_key_file else QMessageBox.No)
    vault = open_vault(tmp_path / "DEDV")
    assert vault.session.is_unlocked and len(vault.list_files()) == 3
    assert [vault.read_file(m.file_id)[1] for m in vault.list_files()] == [b"aaa", b"bbb", b"ccc"]
    assert len(typed["recovery_keys"]) == 1
    question = [t for kind, t in boxes.shown if kind == "question"][0]
    assert "Delete it now?" in question and "has not been upgraded yet" in question and str(key_file) in question
    assert key_file.exists() != delete_key_file
    logged = "old_key_file_deleted" in [r["action"] for r in vault.audit.entries()]
    assert logged == delete_key_file
    assert ("overwritten and deleted" in boxes.text()) == delete_key_file      # the user is told it is gone
    vault.close()


@pytest.mark.parametrize("accept_partial", [False, True])
def test_upgrade_with_an_unreadable_file_asks_before_going_on(qapp, tmp_path, typed, boxes, accept_partial):
    index = _legacy(tmp_path)
    (tmp_path / "DEDV" / "encrypted_files" / index[1]["encrypted_name"]).write_bytes(b"junk" * 20)
    boxes.answers.append(QMessageBox.Yes if accept_partial else QMessageBox.No)
    vault = open_vault(tmp_path / "DEDV")
    question = [t for kind, t in boxes.shown if kind == "question"][0]
    assert "b.txt" in question and "nothing was changed" in question
    key_file = key_dir() / "DEDV_key.txt"
    if not accept_partial:
        assert vault is None and (tmp_path / "DEDV" / "metadata" / "files.json").exists()
        assert not typed["recovery_keys"] and not lock_held(tmp_path)
    else:
        assert len(vault.list_files()) == 3 and vault.read_file(index[0]["file_id"])[1] == b"aaa"
        assert len([k for k, _ in boxes.shown if k == "question"]) == 1    # deleting the key file is NOT offered
        vault.close()
    assert key_file.exists()


def test_upgrade_cancelled_at_the_password_changes_nothing(qapp, tmp_path, typed):
    _legacy(tmp_path)
    typed["password"] = None
    assert open_vault(tmp_path / "DEDV") is None
    assert (tmp_path / "DEDV" / "metadata" / "files.json").exists()
    assert not (tmp_path / "DEDV" / "metadata" / "vault.db").exists()


# ---- main window: lock button and auto-lock ---------------------------------------------------------
@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    monkeypatch.setattr(QApplication, "quit", staticmethod(lambda: None))
    win = MainWindow(config_for(tmp_path), new_vault(tmp_path / "DEDV"))
    win.show()
    yield win
    win.runner = type("Idle", (), {"busy": False})()
    win.close()


def _unlock_with(monkeypatch, password, on_prompt=lambda: None):
    """The unlock prompt is answered with `password` (None = the user closes it)."""
    def fill(self):
        on_prompt()
        if password is None:
            return QDialog.Rejected
        self.password.setText(password)
        self.try_unlock()
        return self.result()
    monkeypatch.setattr(UnlockDialog, "exec", fill)


def test_lock_button_hides_everything_until_the_password_is_given(window, monkeypatch, tmp_path):
    preview = QDialog(window)                                   # stands for an open file viewer
    preview.show()
    copy = window.temp_files.write("plain.xyz", b"decrypted copy")
    visible_at_prompt = []
    _unlock_with(monkeypatch, PASSWORD, lambda: visible_at_prompt.append(
        (window.isVisible(), window.vault.session.is_unlocked, preview.isVisible(), copy.exists())))
    window.lock_btn.click()
    assert wait_until(lambda: bool(visible_at_prompt) and window.isVisible())
    assert visible_at_prompt == [(False, False, False, False)]  # hidden, locked, viewer closed, temp copy gone
    assert window.vault.session.is_unlocked and window._idle.isActive()
    assert [r["action"] for r in window.vault.audit.entries()][-4:] == ["session_end", "lock", "unlock", "session_start"]


def test_closing_the_unlock_prompt_closes_the_application(window, monkeypatch, tmp_path):
    _unlock_with(monkeypatch, None)
    vault = window.vault
    window.lock_vault()
    assert wait_until(lambda: window.vault is None)             # closeEvent ran
    assert not window.isVisible() and vault.db is None and not lock_held(tmp_path)


def test_auto_lock_after_idle_timeout(window, monkeypatch):
    _unlock_with(monkeypatch, None)
    assert window._idle.isActive() and window._idle.interval() == 10 * 60_000     # default: 10 minutes
    session = window.vault.session
    window._idle.start(40)                                      # a short timeout for the test
    assert wait_until(lambda: not session.is_unlocked, 5)
    assert not window.isVisible()


def test_keyboard_and_mouse_activity_postpone_the_auto_lock(window, monkeypatch):
    import time
    _unlock_with(monkeypatch, None)
    session = window.vault.session
    window._idle.start(300)
    end = time.time() + 1.2                                     # four timeouts' worth of steady typing
    while time.time() < end:
        QApplication.sendEvent(window.lock_btn, QKeyEvent(QEvent.KeyPress, Qt.Key_A, Qt.NoModifier, "a"))
        QApplication.processEvents()
        time.sleep(0.03)
    assert session.is_unlocked and window.isVisible()           # activity kept it open
    assert wait_until(lambda: not session.is_unlocked, 5)       # then idle: it locks


def test_auto_lock_time_comes_from_settings(window):
    window.settings_page.auto_lock.setValue(3)
    window.settings_page._save_auto_lock()
    assert window.config.get("auto_lock_minutes") == 3 and window._idle.interval() == 3 * 60_000
    reloaded = ConfigManager(window.config.path)                # saved for the next start
    reloaded.load()
    assert reloaded.get("auto_lock_minutes") == 3


def test_lock_waits_for_a_running_encryption(window, monkeypatch):
    _unlock_with(monkeypatch, None)
    window.runner = type("Busy", (), {"busy": True})()
    window.lock_vault()
    assert window.vault.session.is_unlocked and window.isVisible() and window._idle.isActive()
    window.runner.busy = False
    session = window.vault.session
    window._idle.start(20)
    assert wait_until(lambda: not session.is_unlocked, 5)


def test_change_password_from_settings(window, typed, boxes):
    typed["first"] = "not the current one"
    window.settings_page.password_btn.click()
    assert "Wrong password" in boxes.text()
    typed["first"] = PASSWORD
    window.settings_page.password_btn.click()
    assert "was changed" in boxes.text()
    window.vault.lock()
    window.vault.session.unlock(NEW_PASSWORD)


def test_change_directory_opens_the_other_vault_or_keeps_the_current_one(window, typed, tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    current = window.vault
    typed["password"] = None                                    # cancelled at the new vault's password
    with pytest.raises(Exception, match="not changed"):
        window.change_directory(other)
    assert window.vault is current and current.session.is_unlocked
    assert window.config.get("vault_directory") == str(tmp_path / "DEDV")
    typed["password"] = NEW_PASSWORD
    window.change_directory(other)
    assert window.vault is not current and current.db is None   # old vault closed
    assert window.vault.vault_dir == other / "DEDV" and window.vault.session.is_unlocked
    assert window.config.get("vault_directory") == str(other / "DEDV")


# ---- developer page -----------------------------------------------------------------------------------
def test_verify_audit_log_button(qapp, tmp_path):
    vault = new_vault(tmp_path / "DEDV")
    page = DeveloperPage(lambda: vault)
    page.verify_btn.click()
    assert "intact" in page.audit_result.text() and "2 entries" in page.audit_result.text()
    vault.lock()
    vault.session.unlock(PASSWORD)
    with vault.db as conn:
        conn.execute("UPDATE audit_log SET detail='edited' WHERE id=2")
    page.verify_btn.click()
    assert "damaged" in page.audit_result.text() and "entry 2 of 5" in page.audit_result.text()
    assert not DeveloperPage().verify_btn.isEnabled()            # no vault open


def test_old_key_file_warning_and_delete_button(qapp, tmp_path, boxes):
    vault = new_vault(tmp_path / "DEDV")
    page = DeveloperPage(lambda: vault)
    assert page.old_key_btn.isHidden() and page.old_key_note.isHidden()      # nothing to warn about
    key_file = key_dir() / "DEDV_key.txt"
    key_file.parent.mkdir(parents=True)
    key_file.write_text("key_id: DEDV\nkey: x")
    page.refresh()
    assert not page.old_key_btn.isHidden() and str(key_file) in page.old_key_note.text()
    page.old_key_btn.click()                                    # question answered No
    assert key_file.exists() and "could never be opened again" in boxes.text()
    boxes.answers.append(QMessageBox.Yes)
    page.old_key_btn.click()
    assert not key_file.exists() and page.old_key_btn.isHidden()
    assert vault.audit.entries()[-1]["action"] == "old_key_file_deleted"


# ---- Windows sign-in sessions -----------------------------------------------------------------------
def session_rows(vault) -> int:
    with vault.db as conn:
        return conn.execute("SELECT COUNT(*) FROM keys.sessions").fetchone()[0]


def no_prompt(monkeypatch):
    monkeypatch.setattr(UnlockDialog, "exec", lambda self: pytest.fail("asked for the password"))


def test_open_vault_with_a_live_session_asks_nothing(qapp, tmp_path, monkeypatch):
    new_vault(tmp_path / "DEDV").close()                        # closing DEDV keeps the session
    no_prompt(monkeypatch)
    vault = open_vault(tmp_path / "DEDV")
    assert vault.session.is_unlocked
    vault.close()


def test_lock_button_ends_the_session(window, monkeypatch):
    at_prompt = []
    _unlock_with(monkeypatch, PASSWORD, lambda: at_prompt.append(session_rows(window.vault)))
    window.lock_btn.click()
    assert wait_until(lambda: bool(at_prompt) and window.isVisible())
    assert at_prompt == [0] and session_rows(window.vault) == 1    # the password starts a new one


def test_idle_auto_lock_ends_the_session(window, monkeypatch):
    at_prompt = []
    _unlock_with(monkeypatch, PASSWORD, lambda: at_prompt.append(session_rows(window.vault)))
    window._idle.start(40)
    assert wait_until(lambda: bool(at_prompt), 5)
    assert at_prompt == [0]


def test_windows_lock_and_unlock(window, monkeypatch):
    no_prompt(monkeypatch)
    preview = QDialog(window)                                   # stands for an open file viewer
    preview.show()
    copy = window.temp_files.write("plain.xyz", b"decrypted copy")
    session = window.vault.session
    window.windows_locked()
    assert not session.is_unlocked and not window.isVisible()
    assert not preview.isVisible() and not copy.exists()
    assert session_rows(window.vault) == 1                      # the session stays
    QApplication.processEvents()
    window.windows_unlocked()
    assert session.is_unlocked and window.isVisible() and window._idle.isActive()


def test_windows_unlock_without_a_session_asks_for_the_password(window, monkeypatch):
    window.windows_locked()
    with window.vault.db as conn:
        conn.execute("DELETE FROM keys.sessions")                # e.g. ended on another computer
    _unlock_with(monkeypatch, PASSWORD)
    window.windows_unlocked()
    assert wait_until(lambda: window.vault.session.is_unlocked and window.isVisible())


def test_windows_unlock_does_not_double_the_prompt(window, monkeypatch):
    prompts = []
    _unlock_with(monkeypatch, PASSWORD, lambda: prompts.append(1))
    window.lock_btn.click()                                     # Lock: the prompt is on its way
    window.windows_unlocked()                                   # not locked by Windows: ignored
    assert wait_until(lambda: bool(prompts) and window.isVisible())
    QApplication.processEvents()
    assert prompts == [1]


def test_windows_lock_waits_for_encryption_and_unlock_cancels_it(window, monkeypatch):
    _unlock_with(monkeypatch, None)                             # any prompt would close DEDV
    window.runner = type("Busy", (), {"busy": True})()
    window.windows_locked()
    assert window.vault.session.is_unlocked                     # never interrupt an encryption
    window.windows_unlocked()
    window.runner.busy = False
    assert not wait_until(lambda: window.vault is None or not window.vault.session.is_unlocked, 3)
    assert window.isVisible()


def test_native_session_messages_are_routed(window, monkeypatch):
    import ctypes
    from ctypes import wintypes
    no_prompt(monkeypatch)
    msg = wintypes.MSG()
    msg.message, msg.wParam = 0x02B1, 7                         # WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK
    assert window.nativeEvent(b"windows_generic_MSG", ctypes.addressof(msg)) == (False, 0)
    assert not window.vault.session.is_unlocked
    msg.wParam = 8                                              # WTS_SESSION_UNLOCK
    window.nativeEvent(b"windows_generic_MSG", ctypes.addressof(msg))
    assert window.vault.session.is_unlocked
