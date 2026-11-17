"""Small Windows 11-style building blocks shared by the pages: side-bar buttons, message bars, cards
with soft shadows (light theme), page header, Settings rows, and the page entrance animation."""
from PySide6.QtCore import (QEvent, QObject, QParallelAnimationGroup, QPoint, QPropertyAnimation, QRect,
                            QRectF, Qt, QVariantAnimation)
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (QFrame, QGraphicsOpacityEffect, QHBoxLayout, QLabel, QPushButton,
                               QVBoxLayout, QWidget)

from ui import styles

# Segoe Fluent Icons / Segoe MDL2 Assets code points
GLYPHS = {"view": "", "upload": "", "edit": "", "settings": "",
          "developer": "", "lock": "", "menu": "",
          "info": "", "success": "", "warning": "", "error": ""}


def icon_font(px: int) -> QFont:
    f = QFont(styles.icon_family())
    f.setPixelSize(px)
    return f


class NavButton(QPushButton):
    """Side-bar entry: icon and label on a see-through fill (Mica shows through), which fades in on
    hover. The icon stays put when the rail is collapsed; the label is simply clipped. The selection
    pill is a separate widget that slides between entries (MainWindow)."""

    def __init__(self, text: str, glyph: str, checkable: bool = True):
        super().__init__(text)
        self.setObjectName("nav")
        self.setCheckable(checkable)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.TabFocus)          # keyboard only, so a click leaves no focus ring
        self.glyph = glyph
        self._keyboard_focus = False
        self._hover = 0.0
        self._fade = QVariantAnimation(self)
        self._fade.valueChanged.connect(self._set_hover)

    def _set_hover(self, value):
        self._hover = float(value)
        self.update()

    def _fade_to(self, target: float):
        self._fade.stop()
        ms = styles.motion(styles.FASTER)
        if not ms:
            return self._set_hover(target)
        self._fade.setDuration(ms)
        self._fade.setStartValue(self._hover)
        self._fade.setEndValue(target)
        self._fade.start()

    def focusInEvent(self, e):
        # Windows shows focus rings only for keyboard navigation, not when a window opens.
        self._keyboard_focus = e.reason() in (Qt.TabFocusReason, Qt.BacktabFocusReason)
        super().focusInEvent(e)

    def enterEvent(self, e):
        self._fade_to(1.0)
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._fade_to(0.0)
        super().leaveEvent(e)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r, g, b, a = styles.color("nav_fill")
        level = (1.0 + 0.5 * self._hover) if self.isChecked() else self._hover
        if level:
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(r, g, b, int(a * level)))
            p.drawRoundedRect(QRectF(self.rect()), 4, 4)
        fg = QColor(styles.color("text" if self.isEnabled() else "disabled"))
        p.setPen(fg)
        p.setFont(icon_font(16))
        p.drawText(QRect(10, 0, 20, self.height()), Qt.AlignCenter, self.glyph)
        p.setFont(self.font())
        p.drawText(QRect(44, 0, max(0, self.width() - 52), self.height()), Qt.AlignVCenter | Qt.AlignLeft,
                   self.text())
        if self.hasFocus() and self._keyboard_focus:
            p.setPen(QPen(fg, 2))
            p.setBrush(Qt.NoBrush)
            p.drawRoundedRect(QRectF(self.rect()).adjusted(1, 1, -1, -1), 4, 4)


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


SHADOW_SIZE = 8           # px of soft edge; CSS: box-shadow: 0 2px 8px rgba(0, 0, 0, .1)


class _ShadowHost(QObject):
    """Installed on the parent of elevated widgets: paints their shadows on the parent before the
    parent paints, so the opaque cards cover the middle and only the soft edge shows. Concentric
    translucent rounded rectangles: no blur effect and nothing rendered off-screen. Light theme only."""

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Paint and styles.color("shadow"):
            r, g, b, a = styles.color("shadow")
            p = QPainter(obj)
            p.setRenderHint(QPainter.Antialiasing)
            p.setClipRegion(event.region())
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(r, g, b, a))
            for child in obj.children():
                if child.isWidgetType() and child.isVisible() and child.property("elevated"):
                    rect = QRectF(child.geometry()).translated(0, 2)
                    for i in range(1, SHADOW_SIZE + 1):
                        p.drawRoundedRect(rect.adjusted(-i, -i, i, i), 8 + i, 8 + i)
            p.end()
        return False


class _Elevated(QObject):
    """Installs the shadow host on an elevated widget's parent once it has one."""

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.ParentChange, QEvent.Show):
            parent = obj.parentWidget()
            if parent is not None and not parent.property("shadowHost"):
                parent.setProperty("shadowHost", True)
                parent.installEventFilter(_shadow_host)
        return False


_shadow_host, _elevated = _ShadowHost(), _Elevated()


def elevate(widget: QWidget) -> QWidget:
    """Give a card-like widget (8 px corners) a soft drop shadow in the light theme."""
    widget.setProperty("elevated", True)
    widget.installEventFilter(_elevated)
    return widget


def enter(widget: QWidget) -> None:
    """Page entrance: fade in and rise 24 px with the Fluent "fast out, slow in" curve.
    Same as CSS opacity + transform: translateY, so it stays on the GPU path in a browser."""
    ms = styles.motion(styles.NORMAL)
    running = widget.property("entering")
    if not ms or running:
        return
    effect = QGraphicsOpacityEffect(widget)
    widget.setGraphicsEffect(effect)
    group = QParallelAnimationGroup(widget)
    fade = QPropertyAnimation(effect, b"opacity", group)
    fade.setDuration(styles.motion(styles.FAST))
    fade.setStartValue(0.0)
    fade.setEndValue(1.0)
    rise = QPropertyAnimation(widget, b"pos", group)
    rise.setDuration(ms)
    rise.setStartValue(widget.pos() + QPoint(0, 24))
    rise.setEndValue(widget.pos())
    rise.setEasingCurve(styles.ease())

    def done():
        widget.setGraphicsEffect(None)            # back to direct painting: no off-screen cost
        widget.setProperty("entering", False)
    group.finished.connect(done)
    widget.setProperty("entering", True)
    group.start(QParallelAnimationGroup.DeleteWhenStopped)


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
    elevate(frame)
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
