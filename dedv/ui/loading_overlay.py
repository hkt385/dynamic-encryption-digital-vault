"""Shared "Encrypting" overlay (circular spinner + text) and the background runner that drives it.

Used by both the Upload page (Encrypt) and the Edit page (Re-encrypt). No progress bar,
percentage or time estimate by design.
"""
import traceback

from PySide6.QtCore import QEvent, QObject, QRectF, QRunnable, Qt, QThreadPool, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from ui.styles import ACCENT, BORDER, PANEL

OVERLAY_TEXT = "Encrypting"


class Spinner(QWidget):
    """Continuously rotating arc."""

    def __init__(self, size: int = 56, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._angle = 0
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._tick)

    def start(self):
        self._timer.start()

    def stop(self):
        self._timer.stop()

    @property
    def running(self) -> bool:
        return self._timer.isActive()

    def _tick(self):
        self._angle = (self._angle + 6) % 360
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w = 5
        rect = QRectF(w, w, self.width() - 2 * w, self.height() - 2 * w)
        p.setPen(QPen(QColor(BORDER), w))
        p.drawEllipse(rect)
        pen = QPen(QColor(ACCENT), w)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, -self._angle * 16, -100 * 16)


class LoadingOverlay(QWidget):
    """Modal overlay covering its parent window. While shown, the window's central widget is
    disabled so neither mouse nor keyboard can reach the page underneath."""

    def __init__(self, window):
        super().__init__(window)
        self._window = window
        self.setAttribute(Qt.WA_StyledBackground, False)
        self.setFocusPolicy(Qt.StrongFocus)
        self.hide()

        card = QWidget()
        card.setObjectName("overlayCard")
        card.setStyleSheet(f"QWidget#overlayCard {{ background: {PANEL}; border: 1px solid {BORDER};"
                           " border-radius: 10px; }")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(36, 28, 36, 28)
        cl.setSpacing(14)
        self.spinner = Spinner()
        self.label = QLabel(OVERLAY_TEXT)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 12pt; font-weight: 600; background: transparent;")
        cl.addWidget(self.spinner, 0, Qt.AlignHCenter)
        cl.addWidget(self.label)

        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)
        lay.addWidget(card)
        window.installEventFilter(self)

    @property
    def active(self) -> bool:
        return self.isVisible()

    def start(self):
        if self.active:
            return
        self.setGeometry(self._window.rect())
        central = self._window.centralWidget()
        if central:
            central.setEnabled(False)
        self.raise_()
        self.show()
        self.spinner.start()
        self.setFocus()

    def stop(self):
        self.spinner.stop()
        self.hide()
        central = self._window.centralWidget()
        if central:
            central.setEnabled(True)

    def eventFilter(self, obj, event):
        window = self.__dict__.get("_window")      # may be gone while the window is being destroyed
        if window is not None and obj is window and event.type() == QEvent.Resize and self.active:
            self.setGeometry(self._window.rect())
        return False

    def paintEvent(self, _):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(10, 12, 15, 170))

    def mousePressEvent(self, e):
        e.accept()

    def keyPressEvent(self, e):
        e.accept()


class _Signals(QObject):
    done = Signal(object)
    failed = Signal(str)


class _Job(QRunnable):
    def __init__(self, fn, signals):
        super().__init__()
        self.fn, self.signals = fn, signals

    def run(self):
        try:
            result = self.fn()
        except Exception as e:      # reported to the GUI thread; never lost
            traceback.print_exc()
            self.signals.failed.emit(f"{type(e).__name__}: {e}")
        else:
            self.signals.done.emit(result)


class TaskRunner(QObject):
    """Runs fn() on a worker thread with the overlay visible; the callbacks run on the GUI thread
    after the overlay is hidden. Only one task can run at a time (second request is refused)."""

    def __init__(self, overlay: LoadingOverlay):
        super().__init__(overlay)
        self.overlay = overlay
        self._signals: _Signals | None = None
        self._on_done = self._on_error = None

    @property
    def busy(self) -> bool:
        return self._signals is not None

    def run(self, fn, on_done, on_error) -> bool:
        if self.busy:
            return False
        self._on_done, self._on_error = on_done, on_error
        self._signals = _Signals()
        self._signals.done.connect(self._finish_ok)
        self._signals.failed.connect(self._finish_err)
        self.overlay.start()                  # visible before any work begins
        QThreadPool.globalInstance().start(_Job(fn, self._signals))
        return True

    def _release(self):
        self.overlay.stop()
        self._signals = None

    def _finish_ok(self, result):
        on_done = self._on_done
        self._release()
        try:
            on_done(result)
        except Exception as e:
            traceback.print_exc()
            self._on_error(f"{type(e).__name__}: {e}")

    def _finish_err(self, message):
        on_error = self._on_error
        self._release()
        on_error(message)
