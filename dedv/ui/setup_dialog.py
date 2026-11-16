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
        self.directory.setPlaceholderText("Select Vault Location")
        choose = QPushButton("Choose Directory")
        choose.clicked.connect(self._choose)
        row = QHBoxLayout()
        row.addWidget(self.directory, 1)
        row.addWidget(choose)
        self.go = QPushButton("Create Vault")
        self.go.setObjectName("primary")
        self.go.clicked.connect(self._finish)
        hint = QLabel("A folder named DEDV will be created inside the location you choose.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(8)
        lay.addWidget(title)
        for text, w in (("User Name", self.name), ("Account Type", self.account)):
            l = QLabel(text)
            l.setObjectName("muted")
            lay.addWidget(l)
            lay.addWidget(w)
        l = QLabel("Vault Location")
        l.setObjectName("muted")
        lay.addWidget(l)
        lay.addLayout(row)
        lay.addWidget(hint)
        lay.addSpacing(8)
        lay.addWidget(self.go)

    def _choose(self):
        d = QFileDialog.getExistingDirectory(self, "Select Vault Location")
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
