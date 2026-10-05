from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton,
                               QVBoxLayout, QWidget)

from models.file_metadata import format_size


class UploadPage(QWidget):
    stored = Signal()

    def __init__(self, get_vault, get_account_type):
        super().__init__()
        self.setObjectName("page")
        self._get_vault = get_vault
        self._get_account_type = get_account_type
        self.paths: list[Path] = []

        title = QLabel("Upload")
        title.setObjectName("title")
        self.select_btn = QPushButton("Select Files")
        self.select_btn.clicked.connect(self.select_files)

        self.heading = QLabel("Selected Files")
        self.heading.setObjectName("sectionLabel")
        self.list_label = QLabel()
        self.list_label.setWordWrap(True)
        self.status = QLabel()
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        self.store_btn = QPushButton("Secure && Store")
        self.store_btn.setObjectName("primary")
        self.store_btn.clicked.connect(self.store)

        row = QHBoxLayout()
        row.addWidget(self.select_btn)
        row.addStretch()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(14)
        lay.addWidget(title)
        lay.addLayout(row)
        lay.addWidget(self.heading)
        lay.addWidget(self.list_label)
        lay.addWidget(self.status)
        lay.addWidget(self.store_btn, 0)
        lay.addStretch()
        self._render()

    def select_files(self):
        names, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        if not names:                       # cancelled
            return
        self.paths = [Path(n) for n in names if Path(n).is_file()]
        skipped = len(names) - len(self.paths)
        self.status.setText(f"{skipped} item(s) skipped because they are not valid files." if skipped else "")
        self._render()

    def _render(self):
        has = bool(self.paths)
        self.heading.setVisible(has)
        self.list_label.setVisible(has)
        self.store_btn.setVisible(has)
        lines = []
        for p in self.paths:
            try:
                size = format_size(p.stat().st_size)
            except OSError:
                size = "unavailable"
            lines.append(f"{p.name}   <span style='color:#8a9099'>"
                         f"{(p.suffix.lstrip('.') or 'file').upper()} · {size}</span>")
        self.list_label.setText("<br>".join(lines))

    def store(self):
        vault = self._get_vault()
        if not vault or not self.paths:
            return
        res = vault.store_files(self.paths, self._get_account_type())
        msg = []
        if res.stored:
            msg.append(f"{len(res.stored)} file(s) stored.")
        if res.notice:
            msg.append(res.notice)
        if res.failed:
            msg.append("Could not store:\n" + "\n".join(f"• {n}: {why}" for n, why in res.failed))
        box = QMessageBox.warning if res.failed else QMessageBox.information
        box(self, "Secure & Store", "\n\n".join(msg))
        if res.stored:
            self.paths = []
            self.status.setText("")
            self._render()
            self.stored.emit()
