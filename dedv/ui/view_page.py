from datetime import datetime

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QHeaderView, QLabel, QMessageBox, QStackedLayout,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from models.file_metadata import format_size
from services.encryption_service import algorithm_name
from services.storage_service import StorageError
from services.vault_service import OperationError
from services.viewer_service import BLOCKED, EXTERNAL, TempFiles, classify
from ui.file_viewer import FileViewerDialog
from ui.styles import LEVEL_COLORS, MUTED

COLUMNS = ("Name", "Type", "Size", "Date Added", "Predicted", "Algorithm", "Security Level")
LEVEL_COLUMN = len(COLUMNS) - 1


class ViewPage(QWidget):
    def __init__(self, get_vault, temp_files: TempFiles | None = None):
        super().__init__()
        self.setObjectName("page")
        self._get_vault = get_vault
        self.temp_files = temp_files or TempFiles()

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)   # read-only
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setFocusPolicy(Qt.NoFocus)
        self.table.cellDoubleClicked.connect(self._on_double_click)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for i in range(1, len(COLUMNS)):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        header.setMinimumSectionSize(110)

        empty = QWidget()
        el = QVBoxLayout(empty)
        el.setAlignment(Qt.AlignCenter)
        t = QLabel("No files in your vault yet.")
        t.setObjectName("title")
        t.setAlignment(Qt.AlignCenter)
        s = QLabel("Upload a file to get started.")
        s.setObjectName("muted")
        s.setAlignment(Qt.AlignCenter)
        el.addWidget(t)
        el.addWidget(s)

        self.stack = QStackedLayout()
        self.stack.addWidget(self.table)
        self.stack.addWidget(empty)
        self.error = QLabel()
        self.error.setObjectName("muted")
        self.error.setAlignment(Qt.AlignCenter)
        self.stack.addWidget(self.error)

        self.hint = QLabel("Double-click a file to open it.")
        self.hint.setObjectName("muted")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.addLayout(self.stack)
        lay.addWidget(self.hint)

    def refresh(self):
        vault = self._get_vault()
        try:
            files = vault.list_files() if vault else []
        except StorageError as e:
            self.error.setText(str(e))
            self.stack.setCurrentIndex(2)
            return
        if not files:
            self.stack.setCurrentIndex(1)
            return
        self.stack.setCurrentIndex(0)
        self.table.setRowCount(len(files))
        for r, m in enumerate(sorted(files, key=lambda m: m.date_added, reverse=True)):
            try:
                date = datetime.fromisoformat(m.date_added).strftime("%d/%m/%Y")
            except ValueError:
                date = m.date_added
            algo = algorithm_name(m.algorithm) if m.algorithm else "AES-256 (legacy)"
            cells = (m.original_name, m.file_type, format_size(m.size_bytes), date,
                     m.predicted_level or "-", algo, m.security_level)
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c == 0:
                    item.setData(Qt.UserRole, m.file_id)
                if c in (4, LEVEL_COLUMN):
                    item.setForeground(QColor(LEVEL_COLORS.get(text, MUTED)))
                self.table.setItem(r, c, item)

    # ---- opening -------------------------------------------------------------------------------
    def _on_double_click(self, row: int, _col: int):
        item = self.table.item(row, 0)
        if item is not None:
            self.open_file(item.data(Qt.UserRole))

    def open_file(self, file_id: str) -> None:
        """Decrypt into memory and preview; unknown types are opened externally only after the
        user confirms; executable types are never launched. The encrypted file is only read."""
        vault = self._get_vault()
        if not vault:
            QMessageBox.warning(self, "Open file", "The vault is not available.")
            return
        try:
            meta, data = vault.read_file(file_id)
        except (OperationError, StorageError) as e:
            QMessageBox.warning(self, "Cannot open file", str(e))
            return
        kind = classify(meta.original_name)
        if kind == BLOCKED:
            QMessageBox.warning(self, "Cannot open file",
                                f"{meta.original_name} is an executable or script-host file type. "
                                "DEDV does not launch these.")
        elif kind == EXTERNAL:
            self._open_external(meta.original_name, data)
        else:
            dlg = FileViewerDialog(meta.original_name, kind, data, self)
            if dlg.error:
                QMessageBox.warning(self, "Cannot display file", dlg.error)
            else:
                dlg.exec()

    def _open_external(self, name: str, data: bytes) -> None:
        ok = QMessageBox.question(
            self, "Open externally?",
            f"DEDV has no built-in preview for {name}.\n\nTo open it, a decrypted copy must be written "
            "to a temporary folder and opened by another program. It is deleted when DEDV exits "
            "(or at the next start if the program still has it open).\n\nOpen it?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if ok != QMessageBox.Yes:
            return
        try:
            path = self.temp_files.write(name, data)
        except OSError as e:
            QMessageBox.warning(self, "Cannot open file", f"Temporary copy failed: {e.strerror or e}")
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(path))):
            self.temp_files.cleanup()
            QMessageBox.warning(self, "Cannot open file", "No program could open this file type.")
