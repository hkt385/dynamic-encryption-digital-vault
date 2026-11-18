from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QComboBox, QDialog, QFileDialog, QGridLayout, QLineEdit, QMessageBox,
                               QPushButton, QSpinBox, QWidget)

from config.config_manager import ACCOUNT_TYPES, ConfigError
from services.auth_service import AuthError
from ui.unlock_dialog import NewPasswordDialog, busy_cursor
from ui.widgets import card, label, page_layout, setting_row


class SettingsPage(QWidget):
    changed = Signal()

    def __init__(self, config, change_directory, get_vault=lambda: None):
        super().__init__()
        self.setObjectName("page")
        self.config = config
        self._change_directory = change_directory   # callable(Path) -> None, raises on failure
        self._get_vault = get_vault

        self.username = QLineEdit()
        self.username.setFixedWidth(260)
        self.username.editingFinished.connect(self._save_username)
        self.account = QComboBox()
        self.account.addItems(ACCOUNT_TYPES)
        self.account.setFixedWidth(260)
        self.account.activated.connect(self._save_account)
        self.default_dir = QLineEdit()
        self.default_dir.setReadOnly(True)
        self.vault_dir = QLineEdit()
        self.vault_dir.setReadOnly(True)
        btn = QPushButton("Change folder")
        btn.clicked.connect(self._pick_directory)
        self.auto_lock = QSpinBox()
        self.auto_lock.setRange(1, 240)
        self.auto_lock.setSuffix(" min")
        self.auto_lock.setFixedWidth(120)
        self.auto_lock.lineEdit().setTextMargins(6, 0, 0, 0)    # style-sheet padding does not reach it
        self.auto_lock.editingFinished.connect(self._save_auto_lock)
        self.password_btn = QPushButton("Change password")
        self.password_btn.clicked.connect(self._change_password)

        folders = QWidget()                  # the two paths stacked, with the button beside them
        fl = QGridLayout(folders)
        fl.setContentsMargins(0, 0, 0, 0)
        fl.setHorizontalSpacing(12)
        fl.setVerticalSpacing(6)
        for r, (text, field) in enumerate((("Vault folder", self.vault_dir), ("Created in", self.default_dir))):
            fl.addWidget(label(text, "caption"), r, 0)
            fl.addWidget(field, r, 1)
        fl.setColumnStretch(1, 1)
        storage, sl = card()
        sl.addWidget(label("Vault location"))
        sl.addWidget(label("Where the encrypted files and their keys are kept.", "caption"))
        sl.addSpacing(4)
        sl.addWidget(folders)
        sl.addWidget(btn, 0, Qt.AlignRight)

        lay, _ = page_layout(self, "Settings")
        lay.setSpacing(4)
        for heading, rows in (
                ("Account", [setting_row("User name", "Shown in the side bar.", self.username),
                             setting_row("Account type", "Enterprise vaults can also store files at the High "
                                         "and Critical levels.", self.account)]),
                ("Storage", [storage]),
                ("Security", [setting_row("Lock automatically", "Lock the vault after this many minutes "
                                          "without keyboard or mouse activity.", self.auto_lock),
                              setting_row("Password", "Files are not re-encrypted; the recovery key stays "
                                          "the same.", self.password_btn)])):
            lay.addSpacing(12)
            lay.addWidget(label(heading, "section"))
            lay.addSpacing(4)
            for row in rows:
                lay.addWidget(row)
        lay.addStretch()
        self.setMaximumWidth(860)

    def refresh(self):
        self.username.setText(self.config.get("username"))
        self.account.setCurrentText(self.config.get("account_type", "Personal"))
        self.default_dir.setText(self.config.get("default_directory"))
        self.vault_dir.setText(self.config.get("vault_directory"))
        try:
            self.auto_lock.setValue(int(self.config.get("auto_lock_minutes", 10)))
        except (TypeError, ValueError):
            self.auto_lock.setValue(10)
        self.password_btn.setEnabled(self._get_vault() is not None)

    def _save(self, **values):
        try:
            self.config.update(**values)
        except ConfigError as e:
            QMessageBox.warning(self, "Settings", str(e))
            return
        self.changed.emit()

    def _save_username(self):
        name = self.username.text().strip()
        if not name:
            self.username.setText(self.config.get("username"))
        elif name != self.config.get("username"):
            self._save(username=name)

    def _save_account(self):
        self._save(account_type=self.account.currentText())

    def _save_auto_lock(self):
        if self.auto_lock.value() != self.config.get("auto_lock_minutes", 10):
            self._save(auto_lock_minutes=self.auto_lock.value())

    def _change_password(self):
        vault = self._get_vault()
        if vault is None:
            return
        dlg = NewPasswordDialog("Change password", "Enter the current vault password, then the new one. "
                                "Files are not re-encrypted; the recovery key stays the same.",
                                "Current password", self)
        if dlg.exec() != QDialog.Accepted:
            return
        try:
            with busy_cursor():
                vault.session.change_password(dlg.first_value, dlg.password)
        except AuthError as e:
            QMessageBox.warning(self, "Change password", str(e))
            return
        QMessageBox.information(self, "Change password", "The vault password was changed.")

    def _pick_directory(self):
        chosen = QFileDialog.getExistingDirectory(self, "Choose the vault location",
                                                  self.config.get("default_directory"))
        if not chosen:
            return
        try:
            self._change_directory(Path(chosen))
        except Exception as e:  # StorageError / ConfigError carry user-safe messages
            QMessageBox.warning(self, "Change folder", str(e))
            return
        self.refresh()
