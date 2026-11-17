"""Small Windows 11-style building blocks shared by the pages."""
from PySide6.QtCore import QRect, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from ui import styles

# Segoe Fluent Icons / Segoe MDL2 Assets code points
GLYPHS = {"view": "", "upload": "", "edit": "", "settings": "",
          "developer": "", "lock": "",
          "info": "", "success": "", "warning": "", "error": ""}


def icon_font(px: int) -> QFont:
    f = QFont(styles.icon_family())
    f.setPixelSize(px)
    return f


class NavButton(QPushButton):
    """Side-bar entry: icon, label, and the Windows 11 accent pill when selected."""

    def __init__(self, text: str, glyph: str, checkable: bool = True):
        super().__init__(text)
        self.setObjectName("nav")
        self.setCheckable(checkable)
        self.setCursor(Qt.PointingHandCursor)
        self.glyph = glyph

    def paintEvent(self, e):
        super().paintEvent(e)
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setFont(icon_font(16))
        p.setPen(QColor(styles.color("text" if self.isEnabled() else "disabled")))
        p.drawText(QRect(12, 0, 20, self.height()), Qt.AlignCenter, self.glyph)
        if self.isChecked():
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(styles.color("accent")))
            p.drawRoundedRect(QRectF(0, (self.height() - 16) / 2, 3, 16), 1.5, 1.5)


class InfoBar(QFrame):
    """Message with an icon; severity info / success / warning / error. Hidden while empty.
    Same setText()/text() as a QLabel, so callers and tests can treat it like one."""

    def __init__(self):
        super().__init__()
        self.setObjectName("infoBar")
        self._icon = QLabel()
        self._icon.setObjectName("infoIcon")
        self._label = QLabel()
        self._label.setWordWrap(True)
        self._label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(12)
        lay.addWidget(self._icon, 0, Qt.AlignTop)
        lay.addWidget(self._label, 1)
        self.setText("")

    def setText(self, text: str, severity: str = "info"):
        self._label.setText(text)
        self._icon.setText(GLYPHS[severity])
        self.setProperty("severity", severity)
        for w in (self, self._icon):
            w.style().unpolish(w)
            w.style().polish(w)
        self.setVisible(bool(text))

    def text(self) -> str:
        return self._label.text()

    def severity(self) -> str:
        return self.property("severity")


def label(text: str = "", name: str = "", wrap: bool = False) -> QLabel:
    lbl = QLabel(text)
    if name:
        lbl.setObjectName(name)
    lbl.setWordWrap(wrap)
    return lbl


def page_layout(page: QWidget, title: str, subtitle: str = "") -> tuple[QVBoxLayout, QLabel]:
    """Standard page: padding, title and a one-line explanation. Returns (layout, subtitle label)."""
    lay = QVBoxLayout(page)
    lay.setContentsMargins(36, 28, 36, 28)
    lay.setSpacing(12)
    lay.addWidget(label(title, "title"))
    sub = label(subtitle, "muted", wrap=True)
    sub.setVisible(bool(subtitle))
    lay.addWidget(sub)
    lay.addSpacing(8)
    return lay, sub


def card(layout_cls=QVBoxLayout, margins=(16, 14, 16, 14), spacing=8) -> tuple[QFrame, object]:
    frame = QFrame()
    frame.setObjectName("card")
    lay = layout_cls(frame)
    lay.setContentsMargins(*margins)
    lay.setSpacing(spacing)
    return frame, lay


def setting_row(title: str, description: str, control: QWidget) -> QFrame:
    """Windows Settings-style row: title and description on the left, the control on the right."""
    frame, lay = card(QHBoxLayout, margins=(16, 12, 16, 12), spacing=16)
    text = QVBoxLayout()
    text.setSpacing(2)
    text.addWidget(label(title))
    if description:
        text.addWidget(label(description, "caption", wrap=True))
    lay.addLayout(text, 1)
    lay.addWidget(control, 0, Qt.AlignVCenter)
    return frame
