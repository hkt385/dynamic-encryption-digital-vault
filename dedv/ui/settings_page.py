from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QComboBox, QFileDialog, QLabel, QLineEdit, QMessageBox,
                               QPushButton, QVBoxLayout, QWidget)

from config.config_manager import ACCOUNT_TYPES, ConfigError


class SettingsPage(QWidget):
    changed = Signal()

    def __init__(self, config, change_directory):
        super().__init__()
        self.setObjectName("page")
        self.config = config
        self._change_directory = change_directory   # callable(Path) -> None, raises on failure

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

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(8)
        lay.addWidget(title)
        for label, widget in (("USER", None), ("User Name", self.username),
                              ("ACCOUNT TYPE", None), (None, self.account),
                              ("STORAGE", None), ("Default Directory", self.default_dir),
                              ("Vault Directory", self.vault_dir)):
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
                lay.addWidget(widget)
        lay.addSpacing(6)
        lay.addWidget(btn, 0, Qt.AlignLeft)
        lay.addStretch()
        self.setMaximumWidth(620)

    def refresh(self):
        self.username.setText(self.config.get("username"))
        self.account.setCurrentText(self.config.get("account_type", "Personal"))
        self.default_dir.setText(self.config.get("default_directory"))
        self.vault_dir.setText(self.config.get("vault_directory"))

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
