from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QHeaderView, QLabel, QStackedLayout,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from models.file_metadata import format_size
from services.storage_service import StorageError
from ui.styles import LEVEL_COLORS, MUTED

COLUMNS = ("Name", "Type", "Size", "Date Added", "Security Level")


class ViewPage(QWidget):
    def __init__(self, get_vault):
        super().__init__()
        self.setObjectName("page")
        self._get_vault = get_vault

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)   # read-only
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setFocusPolicy(Qt.NoFocus)
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

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.addLayout(self.stack)

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
            cells = (m.original_name, m.file_type, format_size(m.size_bytes), date, m.security_level)
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c == 4:
                    item.setForeground(QColor(LEVEL_COLORS.get(text, MUTED)))
                self.table.setItem(r, c, item)
