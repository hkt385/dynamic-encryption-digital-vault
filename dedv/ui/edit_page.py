from PySide6.QtCore import Signal
from PySide6.QtWidgets import QComboBox, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from models.file_metadata import format_size
from services.encryption_service import LEVEL_ALGORITHM, algorithm_name
from services.security_decision_service import ENTERPRISE_FINAL_LEVELS, PERSONAL_LEVELS
from services.storage_service import StorageError
from services.vault_service import OperationError


def levels_for(account_type: str) -> tuple[str, ...]:
    """Target levels an account may choose: Personal never sees High or Critical."""
    return {"Personal": PERSONAL_LEVELS, "Enterprise": ENTERPRISE_FINAL_LEVELS}.get(account_type, ())


class EditPage(QWidget):
    """Change the security level (and therefore the algorithm) of an already encrypted file."""
    changed = Signal()

    def __init__(self, get_vault, get_account_type, runner):
        super().__init__()
        self.setObjectName("page")
        self._get_vault = get_vault
        self._get_account_type = get_account_type
        self.runner = runner
        self._files = []

        title = QLabel("Edit")
        title.setObjectName("title")
        intro = QLabel("Change the encryption level of a file that is already in the vault. "
                       "The file is decrypted and encrypted again with the new algorithm.")
        intro.setObjectName("muted")
        intro.setWordWrap(True)

        self.file_combo = QComboBox()
        self.file_combo.activated.connect(self._show_selected)
        self.details = {}
        self.target = QComboBox()
        self.target.activated.connect(lambda _=0: self._update_button())
        self.button = QPushButton("Re-encrypt")
        self.button.setObjectName("primary")
        self.button.clicked.connect(self.reencrypt)
        self.status = QLabel()
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(8)
        lay.addWidget(title)
        lay.addWidget(intro)
        lay.addSpacing(8)
        self._add(lay, "FILE", self.file_combo)
        for key in ("File name", "Current algorithm", "Current security level", "Type", "Size"):
            label = QLabel()
            self.details[key] = label
            lay.addWidget(self._caption(key))
            lay.addWidget(label)
        self._add(lay, "NEW SECURITY LEVEL", self.target)
        lay.addSpacing(6)
        lay.addWidget(self.button)
        lay.addWidget(self.status)
        lay.addStretch()
        self.setMaximumWidth(620)

    @staticmethod
    def _caption(text: str) -> QLabel:
        c = QLabel(text)
        c.setObjectName("muted")
        return c

    def _add(self, lay, text, widget):
        lay.addSpacing(8)
        c = QLabel(text)
        c.setObjectName("sectionLabel")
        lay.addWidget(c)
        lay.addWidget(widget)

    # ---- state ---------------------------------------------------------------------------------
    def refresh(self, keep_id: str | None = None):
        vault = self._get_vault()
        if keep_id is None and self.file_combo.currentIndex() >= 0:
            keep_id = self.file_combo.currentData()
        try:
            self._files = sorted(vault.list_files(), key=lambda m: m.original_name.lower()) if vault else []
        except StorageError as e:
            self._files = []
            self.status.setText(str(e))
        self.file_combo.clear()
        for m in self._files:
            self.file_combo.addItem(m.original_name, m.file_id)
        idx = self.file_combo.findData(keep_id) if keep_id else -1
        self.file_combo.setCurrentIndex(max(idx, 0) if self._files else -1)
        self._show_selected()

    def _current(self):
        i = self.file_combo.currentIndex()
        return self._files[i] if 0 <= i < len(self._files) else None

    def _show_selected(self, _=0):
        m = self._current()
        values = {"File name": m.original_name, "Current algorithm":
                  (algorithm_name(m.algorithm) if m.algorithm else "AES-256 (legacy entry)"),
                  "Current security level": m.security_level, "Type": m.file_type,
                  "Size": format_size(m.size_bytes)} if m else {}
        for key, label in self.details.items():
            label.setText(values.get(key, "-"))
        self.target.clear()
        if m:
            for level in levels_for(self._get_account_type()):
                if level != m.security_level or not m.algorithm:
                    self.target.addItem(f"{level}  ({algorithm_name(LEVEL_ALGORITHM[level])})", level)
        self._update_button()

    def _update_button(self):
        ready = self._current() is not None and self.target.count() > 0 and not self.runner.busy
        self.button.setEnabled(ready)
        if not self._files:
            self.status.setText("There are no files in the vault yet.")
        elif self.target.count() == 0:
            self.status.setText("No other security level is available for this account type.")

    # ---- re-encrypt ----------------------------------------------------------------------------
    def reencrypt(self):
        vault, m = self._get_vault(), self._current()
        level = self.target.currentData()
        if not vault or m is None or not level or self.runner.busy:
            return
        account = self._get_account_type()
        self.button.setEnabled(False)
        self.status.setText("")
        file_id, name = m.file_id, m.original_name

        def work():
            return vault.reencrypt(file_id, level, account)

        def done(new_meta):
            self.refresh(keep_id=file_id)
            self.changed.emit()
            QMessageBox.information(self, "Re-encrypt",
                                    f"{name} is now {new_meta.security_level} "
                                    f"({algorithm_name(new_meta.algorithm)}).")

        def failed(message):
            self._update_button()
            self.status.setText(message)
            QMessageBox.warning(self, "Re-encrypt", message if not message.startswith("OperationError: ")
                                else message[len("OperationError: "):])

        self.runner.run(work, done, failed)
