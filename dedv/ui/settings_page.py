from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QComboBox, QDialog, QFileDialog, QLabel, QLineEdit, QMessageBox,
                               QPushButton, QSpinBox, QVBoxLayout, QWidget)

from config.config_manager import ACCOUNT_TYPES, ConfigError
from services.auth_service import AuthError
from ui.unlock_dialog import NewPasswordDialog, busy_cursor


class SettingsPage(QWidget):
    changed = Signal()

    def __init__(self, config, change_directory, get_vault=lambda: None):
        super().__init__()
        self.setObjectName("page")
        self.config = config
        self._change_directory = change_directory   # callable(Path) -> None, raises on failure
        self._get_vault = get_vault

        title = QLabel("Settings")
        title.setObjectName("title")

        self.username = QLineEdit()
        self.username.editingFinished.connect(self._save_username)
        self.account = QComboBox()
        self.account.addItems(ACCOUNT_TYPES)
        self.account.activated.connect(self._save_account)
        self.default_dir = QLineEdit()
        self.default_dir.setReadOnly(True)
        self.vault_dir = QLineEdit()
        self.vault_dir.setReadOnly(True)
        btn = QPushButton("Change Directory")
        btn.clicked.connect(self._pick_directory)
        self.auto_lock = QSpinBox()
        self.auto_lock.setRange(1, 240)
        self.auto_lock.setSuffix(" min")
        self.auto_lock.setToolTip("The vault locks itself after this long without keyboard or mouse activity.")
        self.auto_lock.editingFinished.connect(self._save_auto_lock)
        self.password_btn = QPushButton("Change Password")
        self.password_btn.clicked.connect(self._change_password)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(8)
        lay.addWidget(title)
        for label, widget in (("USER", None), ("User Name", self.username),
                              ("ACCOUNT TYPE", None), (None, self.account),
                              ("STORAGE", None), ("Default Directory", self.default_dir),
                              ("Vault Directory", self.vault_dir), (None, btn),
                              ("SECURITY", None), ("Lock automatically when idle for", self.auto_lock),
                              (None, self.password_btn)):
            if label and widget is None:
                lay.addSpacing(14)
                lbl = QLabel(label)
                lbl.setObjectName("sectionLabel")
                lay.addWidget(lbl)
            else:
                if label:
                    lbl = QLabel(label)
                    lbl.setObjectName("muted")
                    lay.addWidget(lbl)
                if isinstance(widget, (QPushButton, QSpinBox)):
                    lay.addWidget(widget, 0, Qt.AlignLeft)
                else:
                    lay.addWidget(widget)
        lay.addStretch()
        self.setMaximumWidth(620)

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
        chosen = QFileDialog.getExistingDirectory(self, "Select Vault Location",
                                                  self.config.get("default_directory"))
        if not chosen:
            return
        try:
            self._change_directory(Path(chosen))
        except Exception as e:  # StorageError / ConfigError carry user-safe messages
            QMessageBox.warning(self, "Change Directory", str(e))
            return
        self.refresh()
