from pathlib import Path

from PySide6.QtWidgets import (QComboBox, QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QVBoxLayout)

from config.config_manager import ACCOUNT_TYPES
from services.storage_service import StorageError, create_vault


class SetupDialog(QDialog):
    """First-run setup. On accept, `result` holds the config values."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Welcome to DEDV")
        self.setMinimumWidth(480)
        self.result: dict | None = None

        title = QLabel("Set up your vault")
        title.setObjectName("title")
        self.name = QLineEdit()
        self.name.setPlaceholderText("User name")
        self.account = QComboBox()
        self.account.addItems(ACCOUNT_TYPES)
        self.directory = QLineEdit()
        self.directory.setReadOnly(True)
        self.directory.setPlaceholderText("No folder chosen")
        choose = QPushButton("Choose folder")
        choose.clicked.connect(self._choose)
        row = QHBoxLayout()
        row.addWidget(self.directory, 1)
        row.addWidget(choose)
        self.go = QPushButton("Create vault")
        self.go.setObjectName("primary")
        self.go.setMinimumWidth(120)
        self.go.clicked.connect(self._finish)
        hint = QLabel("A folder named DEDV will be created inside the location you choose.")
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        bottom = QHBoxLayout()
        bottom.addStretch()
        bottom.addWidget(self.go)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(6)
        lay.addWidget(title)
        lay.addSpacing(8)
        for text, w in (("User name", self.name), ("Account type", self.account)):
            lay.addWidget(QLabel(text))
            lay.addWidget(w)
            lay.addSpacing(6)
        lay.addWidget(QLabel("Vault location"))
        lay.addLayout(row)
        lay.addWidget(hint)
        lay.addSpacing(12)
        lay.addLayout(bottom)

    def _choose(self):
        d = QFileDialog.getExistingDirectory(self, "Choose the vault location")
        if d:
            self.directory.setText(str(Path(d)))

    def _finish(self):
        name, parent = self.name.text().strip(), self.directory.text().strip()
        if not name:
            QMessageBox.warning(self, "Setup", "Please enter a user name.")
            return
        if not parent:
            QMessageBox.warning(self, "Setup", "Please choose a vault location.")
            return
        try:
            vault = create_vault(Path(parent))
        except StorageError as e:
            QMessageBox.warning(self, "Setup", str(e))
            return
        self.result = {"username": name, "account_type": self.account.currentText(),
                       "default_directory": parent, "vault_directory": str(vault)}
        self.accept()
