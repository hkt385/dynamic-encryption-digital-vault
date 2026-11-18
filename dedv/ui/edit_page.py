from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QComboBox, QGridLayout, QHBoxLayout, QLabel, QMessageBox, QPushButton,
                               QWidget)

from models.file_metadata import format_size
from services.encryption_service import LEVEL_ALGORITHM, algorithm_name
from services.security_decision_service import account_levels, floor_level
from services.storage_service import StorageError
from services.vault_service import OperationError
from ui.upload_page import fill_levels
from ui.widgets import InfoBar, card, label, page_layout


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

        self.file_combo = QComboBox()
        self.file_combo.activated.connect(self._show_selected)
        self.details = {}
        self.target = QComboBox()
        self.target.activated.connect(lambda _=0: self._update_button())
        self.button = QPushButton("Re-encrypt")
        self.button.setObjectName("primary")
        self.button.setMinimumWidth(120)
        self.button.clicked.connect(self.reencrypt)
        self.status = InfoBar()

        # One card: pick the file, see where it stands, pick the new level.
        box, grid = card(QGridLayout, margins=(16, 16, 16, 16), spacing=10)
        grid.setColumnMinimumWidth(0, 160)
        grid.setColumnStretch(1, 1)
        rows = [("File", self.file_combo)]
        for key in ("File name", "Current algorithm", "Current security level", "Type", "Size"):
            self.details[key] = QLabel()
            rows.append((key, self.details[key]))
        rows.append(("New security level", self.target))
        for r, (text, widget) in enumerate(rows):
            grid.addWidget(label(text, "muted"), r, 0)
            grid.addWidget(widget, r, 1)

        bottom = QHBoxLayout()
        bottom.addStretch()
        bottom.addWidget(self.button)
        lay, _ = page_layout(self, "Edit", "Change the security level of a file that is already in the vault. "
                                           "The file is decrypted and encrypted again with the new algorithm.")
        lay.addWidget(box)
        lay.addLayout(bottom)
        lay.addWidget(self.status)
        lay.addStretch()
        self.setMaximumWidth(760)

    # ---- state ---------------------------------------------------------------------------------
    def refresh(self, keep_id: str | None = None):
        vault = self._get_vault()
        if keep_id is None and self.file_combo.currentIndex() >= 0:
            keep_id = self.file_combo.currentData()
        try:
            self._files = sorted(vault.list_files(), key=lambda m: m.original_name.lower()) if vault else []
        except StorageError as e:
            self._files = []
            self.status.setText(str(e), "error")
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
        values = {"File name": m.original_name, "Current algorithm": algorithm_name(m.algorithm),
                  "Current security level": m.security_level, "Type": m.file_type,
                  "Size": format_size(m.size_bytes)} if m else {}
        for key, label in self.details.items():
            label.setText(values.get(key, "-"))
        self.target.clear()
        if m:
            # Never below the stored prediction; files upgraded without one keep their current level
            # as the floor (VaultService.reencrypt enforces the same rule).
            floor = floor_level(m.predicted_level) or m.security_level
            why = (f"Below the predicted level {m.predicted_level}." if floor_level(m.predicted_level)
                   else f"Below the current level {floor}; no prediction was recorded for this file.")
            fill_levels(self.target,
                        [lv for lv in account_levels(self._get_account_type()) if lv != m.security_level],
                        floor, why + " The level may be raised but not lowered.",
                        lambda lv: f"{lv}  ({algorithm_name(LEVEL_ALGORITHM[lv])})")
            enabled = [i for i in range(self.target.count()) if self.target.model().item(i).isEnabled()]
            self.target.setCurrentIndex(enabled[0] if enabled else -1)
        self._update_button()

    def _update_button(self):
        ready = self._current() is not None and self.target.currentIndex() >= 0 and not self.runner.busy
        self.button.setEnabled(ready)
        if not self._files:
            self.status.setText("There are no files in the vault yet.")
        elif self.target.currentIndex() < 0:
            self.status.setText("No higher security level is available for this file and account type.")
        else:
            self.status.setText("")

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
            self.status.setText(message, "error")
            QMessageBox.warning(self, "Re-encrypt", message if not message.startswith("OperationError: ")
                                else message[len("OperationError: "):])

        self.runner.run(work, done, failed)
