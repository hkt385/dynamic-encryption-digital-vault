"""Vault password dialogs, and open_vault(): the one way the UI opens (and unlocks) a vault."""
from contextlib import contextmanager
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QVBoxLayout)

from services import migration_service
from services.auth_service import (MIN_PASSWORD_LENGTH, AuthError, AuthSession, check_password,
                                   password_strength)
from services.storage_service import StorageError
from services.vault_service import VaultService
from ui import backdrop


@contextmanager
def busy_cursor():
    """Key derivation (Argon2id) takes up to about a second by design; show that the app is working."""
    QApplication.setOverrideCursor(Qt.WaitCursor)
    QApplication.processEvents()
    try:
        yield
    finally:
        QApplication.restoreOverrideCursor()


def _password_field(placeholder: str) -> QLineEdit:
    f = QLineEdit()
    f.setEchoMode(QLineEdit.Password)
    f.setPlaceholderText(placeholder)
    return f


class NewPasswordDialog(QDialog):
    """Choose a new vault password. `first` adds a field above it: the current password
    (change) or the recovery key (reset). On accept: .password and .first_value."""

    def __init__(self, title: str, intro: str, first: str = "", parent=None):
        super().__init__(parent)
        backdrop.prepare(self)                 # Mica (main window) / Acrylic (dialog)
        self.setWindowTitle(title)
        self.setMinimumWidth(480)
        self.password = self.first_value = ""
        heading = QLabel(title)
        heading.setObjectName("title")
        text = QLabel(intro)
        text.setWordWrap(True)
        self.first = None
        if first:
            self.first = QLineEdit() if first == "Recovery key" else _password_field(first)
            self.first.setPlaceholderText(first)
        self.new = _password_field(f"New password (at least {MIN_PASSWORD_LENGTH} characters)")
        self.confirm = _password_field("Repeat the new password")
        self.hint = QLabel()
        self.hint.setObjectName("muted")
        self.new.textChanged.connect(lambda t: self.hint.setText(f"Strength: {password_strength(t)}" if t else ""))
        self.error = QLabel()
        self.error.setObjectName("error")
        self.error.setWordWrap(True)
        ok = QPushButton("Continue")
        ok.setObjectName("primary")
        ok.setDefault(True)
        ok.clicked.connect(self._finish)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(cancel)
        row.addWidget(ok)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(8)
        for w in (heading, text, self.first, self.new, self.confirm, self.hint, self.error):
            if w is not None:
                lay.addWidget(w)
        lay.addLayout(row)

    def _finish(self):
        try:
            check_password(self.new.text())
        except AuthError as e:
            self.error.setText(str(e))
            return
        if self.new.text() != self.confirm.text():
            self.error.setText("The two passwords are not the same.")
            return
        if self.first is not None and not self.first.text().strip():
            self.error.setText(f"{self.first.placeholderText()} is required.")
            return
        self.password = self.new.text()
        self.first_value = self.first.text() if self.first is not None else ""
        self.accept()


class RecoveryKeyDialog(QDialog):
    """Shows the recovery key once. It cannot be closed until the user confirms it is saved."""

    def __init__(self, recovery_key: str, parent=None):
        super().__init__(parent)
        backdrop.prepare(self)                 # Mica (main window) / Acrylic (dialog)
        self.setWindowTitle("Your recovery key")
        self.setMinimumWidth(560)
        heading = QLabel("Save your recovery key")
        heading.setObjectName("title")
        text = QLabel("If you forget the vault password, this key is the ONLY way back into the vault. "
                      "It is shown once and is not stored anywhere. Write it down or print it, and keep "
                      "it away from this computer. Anyone who has it can open the vault.")
        text.setWordWrap(True)
        self.key = QLineEdit(recovery_key)
        self.key.setReadOnly(True)
        self.key.setFont(QFont("Consolas", 11))
        copy = QPushButton("Copy")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(recovery_key))
        row = QHBoxLayout()
        row.addWidget(self.key, 1)
        row.addWidget(copy)
        self.saved = QCheckBox("I have saved the recovery key in a safe place")
        self.done_btn = QPushButton("Continue")
        self.done_btn.setObjectName("primary")
        self.done_btn.setEnabled(False)
        self.saved.toggled.connect(self.done_btn.setEnabled)
        self.done_btn.clicked.connect(self.accept)
        bottom = QHBoxLayout()
        bottom.addWidget(self.saved, 1)
        bottom.addWidget(self.done_btn)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(12)
        lay.addWidget(heading)
        lay.addWidget(text)
        lay.addLayout(row)
        lay.addSpacing(8)
        lay.addLayout(bottom)

    def reject(self):                       # Esc / window close: only once the box is ticked
        if self.saved.isChecked():
            super().reject()


class UnlockDialog(QDialog):
    """Asks for the vault password. Accepted = the session is unlocked."""

    def __init__(self, session: AuthSession, vault_path: str = "", parent=None):
        super().__init__(parent)
        backdrop.prepare(self)                 # Mica (main window) / Acrylic (dialog)
        self.session = session
        self.setWindowTitle("Unlock DEDV")
        self.setMinimumWidth(460)
        heading = QLabel("Vault locked")
        heading.setObjectName("title")
        where = QLabel(vault_path)
        where.setObjectName("muted")
        where.setWordWrap(True)
        self.password = _password_field("Vault password")
        self.password.returnPressed.connect(self.try_unlock)
        self.message = QLabel()
        self.message.setObjectName("error")
        self.message.setWordWrap(True)
        self.unlock_btn = QPushButton("Unlock")
        self.unlock_btn.setObjectName("primary")
        self.unlock_btn.clicked.connect(self.try_unlock)
        self.reset_btn = QPushButton("Reset password with recovery key")
        self.reset_btn.clicked.connect(self.reset_password)
        quit_btn = QPushButton("Close")
        quit_btn.clicked.connect(self.reject)
        row = QHBoxLayout()
        row.addWidget(self.reset_btn)
        row.addStretch()
        row.addWidget(quit_btn)
        row.addWidget(self.unlock_btn)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(10)
        for w in (heading, where, self.password, self.message):
            lay.addWidget(w)
        lay.addLayout(row)
        self._countdown = QTimer(self)
        self._countdown.setInterval(500)
        self._countdown.timeout.connect(self._tick)
        self._tick()

    def _tick(self):
        """While a failed-attempt delay runs, Unlock is disabled and the remaining time is shown."""
        wait = self.session.retry_after()
        self.unlock_btn.setEnabled(wait <= 0)
        if wait > 0:
            self.message.setText(f"Too many wrong passwords. Try again in {int(wait) + 1} s.")
            self._countdown.start()
        elif self._countdown.isActive():
            self._countdown.stop()
            self.message.setText("")

    def try_unlock(self):
        if not self.unlock_btn.isEnabled():
            return
        try:
            with busy_cursor():
                self.session.unlock(self.password.text())
        except AuthError as e:
            self.password.clear()
            self.message.setText(str(e))
            if e.retry_after > 0:
                self._tick()
            return
        self.password.clear()
        self.accept()

    def reset_password(self):
        dlg = NewPasswordDialog("Reset password", "Enter the recovery key you saved when the vault "
                                "password was created, then choose a new password.", "Recovery key", self)
        if dlg.exec() != QDialog.Accepted:
            return
        try:
            with busy_cursor():
                self.session.reset_with_recovery_key(dlg.first_value, dlg.password)
        except AuthError as e:
            self.message.setText(str(e))
            return
        QMessageBox.information(self, "Reset password", "The password was changed. "
                                "Your recovery key stays the same.")
        self.accept()


def _first_password(vault: VaultService, parent) -> bool:
    dlg = NewPasswordDialog("Create a vault password",
                            "This password protects every key in the vault. You will need it each time "
                            "you start DEDV. There is no way to recover files without it or the recovery "
                            "key shown in the next step.", parent=parent)
    if dlg.exec() != QDialog.Accepted:
        return False
    with busy_cursor():
        recovery_key = vault.session.initialize(dlg.password)
    RecoveryKeyDialog(recovery_key, parent).exec()
    return True


def _upgrade(vault: VaultService, parent) -> bool:
    """Vault written by DEDV 0.1: create a password and migrate (see migration_service)."""
    dlg = NewPasswordDialog("Upgrade this vault",
                            "This vault was created by an older DEDV version that kept its master key in "
                            "a plain text file. Choose a vault password now; every key will be re-protected "
                            "with it. Nothing is changed unless every file can still be opened afterwards.",
                            parent=parent)
    if dlg.exec() != QDialog.Accepted:
        return False
    try:
        try:
            with busy_cursor():
                result = vault.migrate(dlg.password)
        except migration_service.MigrationVerifyError as e:
            listed = "\n".join(f"• {name}: {why}" for name, why in e.failed[:15])
            more = f"\n… and {len(e.failed) - 15} more" if len(e.failed) > 15 else ""
            if QMessageBox.question(
                    parent, "Upgrade this vault",
                    f"{len(e.failed)} file(s) could not be opened, so nothing was changed:\n\n{listed}{more}\n\n"
                    "Upgrade anyway? The other files will be upgraded. These stay listed but cannot be "
                    "opened, and the old key file and old key stores are kept.",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return False
            with busy_cursor():
                result = vault.migrate(dlg.password, allow_unverified=True)
    except StorageError as e:
        QMessageBox.critical(parent, "Upgrade this vault", str(e))
        return False
    RecoveryKeyDialog(result.recovery_key, parent).exec()

    key_file = migration_service.old_key_file()
    summary = (f"{result.files} file(s) were upgraded. A copy of the old index is in:\n{result.backup_dir}")
    if result.unverified or not key_file.exists():
        QMessageBox.information(parent, "Upgrade this vault", summary)
        return True
    if QMessageBox.question(
            parent, "Delete the old key file?",
            f"{summary}\n\nThe old plain-text key file is no longer needed by THIS vault:\n{key_file}\n\n"
            "Delete it now?\n\nAnswer No if you have any other DEDV vault that has not been upgraded yet: "
            "it shares this key file and could never be opened again without it. You can delete the "
            "file later on the Developer page.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
        try:
            migration_service.delete_old_key_file()
            vault.audit.append("old_key_file_deleted")
            QMessageBox.information(parent, "Old key file", "The old key file was overwritten and deleted.")
        except OSError as e:
            QMessageBox.warning(parent, "Old key file", f"The old key file could not be deleted: {e.strerror or e}")
    return True


def open_vault(vault_dir: Path, parent=None) -> VaultService | None:
    """Open the vault and bring it to the unlocked state, asking the user for whatever is needed
    (unlock, first password, or upgrade of an old vault). A live session of this Windows sign-in
    opens it without asking. None = the user cancelled.
    Raises StorageError if the vault cannot be opened at all."""
    vault = VaultService(vault_dir)
    try:
        if vault.needs_migration:
            ok = _upgrade(vault, parent)
        elif not vault.session.is_initialized:
            ok = _first_password(vault, parent)
        elif vault.session.resume():
            ok = True
        else:
            ok = UnlockDialog(vault.session, str(vault.vault_dir), parent).exec() == QDialog.Accepted
    except Exception:
        vault.close()
        raise
    if not ok:
        vault.close()
        return None
    return vault
