from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
from PySide6.QtGui import QPixmap
from PySide6.QtPdf import QPdfDocument
from PySide6.QtPdfWidgets import QPdfView
from PySide6.QtWidgets import (QDialog, QLabel, QPlainTextEdit, QPushButton, QScrollArea,
                               QVBoxLayout)

from services.viewer_service import IMAGE, MAX_TEXT_BYTES, PDF, TEXT


class FileViewerDialog(QDialog):
    """In-memory preview of decrypted content. The bytes are dropped when the dialog closes."""

    def __init__(self, name: str, kind: str, data: bytes, parent=None):
        super().__init__(parent)
        self.setWindowTitle(name)
        self.resize(900, 650)
        self._data = data
        self._buffer = self._pdf = None
        self.error = ""
        lay = QVBoxLayout(self)

        if kind == TEXT:
            view = QPlainTextEdit()
            view.setReadOnly(True)
            text = data[:MAX_TEXT_BYTES].decode("utf-8", errors="replace")
            if len(data) > MAX_TEXT_BYTES:
                text += "\n\n[Preview truncated at 2 MB]"
            view.setPlainText(text)
            self.body = view
        elif kind == IMAGE:
            pix = QPixmap()
            if not pix.loadFromData(data):
                self.body = self._fail("This image is corrupted or in an unsupported format.")
            else:
                label = QLabel()
                label.setPixmap(pix)
                label.setAlignment(Qt.AlignCenter)
                scroll = QScrollArea()
                scroll.setWidget(label)
                scroll.setWidgetResizable(True)
                self.body = scroll
        elif kind == PDF:
            self._buffer = QBuffer()
            self._buffer.setData(QByteArray(data))
            self._buffer.open(QIODevice.ReadOnly)
            self._pdf = QPdfDocument(self)
            self._pdf.load(self._buffer)
            if self._pdf.pageCount() == 0:
                self.body = self._fail("This PDF is corrupted or could not be read.")
            else:
                view = QPdfView()
                view.setDocument(self._pdf)
                view.setPageMode(QPdfView.PageMode.MultiPage)
                self.body = view
        else:
            self.body = self._fail("No preview is available for this file type.")

        note = QLabel("Preview is held in memory only; nothing was written to disk.")
        note.setObjectName("muted")
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        lay.addWidget(self.body, 1)
        lay.addWidget(note)
        lay.addWidget(close)

    def _fail(self, message: str) -> QLabel:
        self.error = message
        label = QLabel(message)
        label.setAlignment(Qt.AlignCenter)
        return label

    def done(self, r):
        self._data = b""
        super().done(r)
