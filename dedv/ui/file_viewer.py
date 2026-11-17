from PySide6.QtCore import QBuffer, QByteArray, QEvent, QIODevice, Qt
from PySide6.QtGui import QGuiApplication, QKeySequence, QPainter, QPixmap, QShortcut, QTransform
from PySide6.QtPdf import QPdfDocument
from PySide6.QtPdfWidgets import QPdfView
from PySide6.QtWidgets import (QDialog, QGraphicsScene, QGraphicsView, QHBoxLayout, QLabel,
                               QPlainTextEdit, QPushButton, QVBoxLayout)

from services.viewer_service import IMAGE, MAX_TEXT_BYTES, PDF, TEXT

ZOOM_STEP = 1.25
ZOOM_MIN, ZOOM_MAX = 0.05, 8.0


class FileViewerDialog(QDialog):
    """In-memory preview of decrypted content. The bytes are dropped when the dialog closes.

    Images and PDFs open fitted to the window and zoom with the -/+/Fit/100% buttons, Ctrl+wheel
    or Ctrl+-/Ctrl+=/Ctrl+0. Text zooms with Ctrl+wheel (built into QPlainTextEdit)."""

    def __init__(self, name: str, kind: str, data: bytes, parent=None):
        super().__init__(parent)
        self.setWindowTitle(name)
        self.resize(900, 650)
        self._data = data
        self._buffer = self._pdf = None
        self._content = None        # (width, height) of images/PDF pages at 100%; None = not zoomable
        self._fit = True
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
                # Scaled by a view transform, so zooming never makes an enlarged copy of the image.
                scene = QGraphicsScene(self)
                scene.addPixmap(pix).setTransformationMode(Qt.SmoothTransformation)
                view = QGraphicsView(scene)
                view.setRenderHint(QPainter.SmoothPixmapTransform)
                view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
                view.setDragMode(QGraphicsView.ScrollHandDrag)
                self.body = view
                self._content = (pix.width(), pix.height())
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
                view.setZoomMode(QPdfView.ZoomMode.Custom)
                # Always shown, so fitting to the width can't toggle it on and off.
                view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
                self.body = view
                # QPdfView renders 1 pt as logicalDPI/72 px at zoom 1.0.
                px = QGuiApplication.primaryScreen().logicalDotsPerInch() / 72
                widest = max(self._pdf.pagePointSize(i).width() for i in range(self._pdf.pageCount()))
                self._content = (widest * px, None)
        else:
            self.body = self._fail("No preview is available for this file type.")

        bar = QHBoxLayout()
        if self._content:
            self.zoom_label = QLabel()
            for text, tip, keys, slot in (
                    ("−", "Zoom out (Ctrl+-, Ctrl+wheel)", [QKeySequence.ZoomOut], self.zoom_out),
                    ("+", "Zoom in (Ctrl+=, Ctrl+wheel)", [QKeySequence.ZoomIn, "Ctrl+="], self.zoom_in),
                    ("Fit", "Fit to window (Ctrl+0)", ["Ctrl+0"], self.fit),
                    ("100%", "Actual size", [], lambda: self.set_zoom(1.0))):
                btn = QPushButton(text)
                btn.setToolTip(tip)
                btn.clicked.connect(slot)
                bar.addWidget(btn)
                for k in keys:
                    QShortcut(QKeySequence(k), self, slot)
            bar.addWidget(self.zoom_label)
            self.body.viewport().installEventFilter(self)
        note = QLabel("Preview is held in memory only; nothing was written to disk.")
        note.setObjectName("muted")
        bar.addStretch(1)
        bar.addWidget(note)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        lay.addWidget(self.body, 1)
        lay.addLayout(bar)
        lay.addWidget(close)
        if self._content:
            self.fit()

    # ---- zoom (images and PDFs) ------------------------------------------------------------------------
    def zoom(self) -> float:
        if isinstance(self.body, QPdfView):
            return self.body.zoomFactor()
        return self.body.transform().m11()

    def set_zoom(self, factor: float, fit: bool = False):
        factor = min(max(factor, ZOOM_MIN), ZOOM_MAX)
        self._fit = fit
        if isinstance(self.body, QPdfView):
            self.body.setZoomFactor(factor)
        else:
            self.body.setTransform(QTransform.fromScale(factor, factor))
        self.zoom_label.setText(f"{factor:.0%}")

    def zoom_in(self):
        self.set_zoom(self.zoom() * ZOOM_STEP)

    def zoom_out(self):
        self.set_zoom(self.zoom() / ZOOM_STEP)

    def fit(self):
        """Whole image in the window (never enlarged past 100%); PDFs fit the page width."""
        vp, (w, h) = self.body.viewport().size(), self._content
        if isinstance(self.body, QPdfView):
            m = self.body.documentMargins()
            factor = (vp.width() - m.left() - m.right()) / w
        else:   # 2 px spare so rounding can't bring up scroll bars, which would shrink the viewport
            factor = min((vp.width() - 2) / w, (vp.height() - 2) / h, 1.0)
        self.set_zoom(factor, fit=True)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Wheel and event.modifiers() & Qt.ControlModifier:
            if event.angleDelta().y():
                (self.zoom_in if event.angleDelta().y() > 0 else self.zoom_out)()
            return True
        if event.type() == QEvent.Resize and self._fit:
            self.fit()
        return super().eventFilter(obj, event)

    def _fail(self, message: str) -> QLabel:
        self.error = message
        label = QLabel(message)
        label.setAlignment(Qt.AlignCenter)
        return label

    def done(self, r):
        self._data = b""
        super().done(r)
