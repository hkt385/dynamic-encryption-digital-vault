"""Windows 11 materials, drawn by the window manager (DWM): Mica behind the main window and Acrylic
behind dialogs (Microsoft: Mica for long-lived windows, Acrylic for transient ones), title bars that
follow light/dark, and rounded corners on drop-down lists and tooltips.

Needs Windows 11 22H2 (build 22621). Anywhere else install() does nothing and the style sheet keeps
solid window colours. With "Transparency effects" off, Windows itself shows a solid colour instead.
"""
import ctypes
import os
import sys

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import QApplication, QDialog, QMainWindow

DWMWA_USE_IMMERSIVE_DARK_MODE = 20
DWMWA_WINDOW_CORNER_PREFERENCE = 33
DWMWA_SYSTEMBACKDROP_TYPE = 38
DWMWCP_ROUNDSMALL = 3
DWMSBT_MAINWINDOW, DWMSBT_TRANSIENTWINDOW = 2, 3          # Mica, Acrylic

_hook = None


def supported(app) -> bool:
    """Windows 11 22H2+. DEDV_NO_MICA=1 turns the materials off (solid colours)."""
    return (sys.platform == "win32" and sys.getwindowsversion().build >= 22621
            and app.platformName() == "windows" and os.environ.get("DEDV_NO_MICA") != "1")


def _set(widget, attribute: int, value: int) -> bool:
    v = ctypes.c_int(value)
    return ctypes.windll.dwmapi.DwmSetWindowAttribute(
        ctypes.c_void_p(int(widget.winId())), attribute, ctypes.byref(v), ctypes.sizeof(v)) == 0


def _material(w) -> int | None:
    if isinstance(w, QMainWindow):
        return DWMSBT_MAINWINDOW
    if isinstance(w, QDialog):
        return DWMSBT_TRANSIENTWINDOW
    return None


def _dark() -> bool:
    from ui import styles
    return styles.is_dark()


def prepare(window) -> None:
    """Call in the window's constructor: the window must be translucent before its native window
    exists (Qt creates it before any event a filter could catch). Main window: Mica; dialog: Acrylic.
    Qt's own message boxes cannot be reached that early and keep a solid themed background."""
    material = _material(window)
    if _hook is not None and material and not window.testAttribute(Qt.WA_WState_Created):
        window.setAttribute(Qt.WA_TranslucentBackground)
        window.setProperty("backdrop", "true")           # style sheet: transparent window background
        window.setProperty("dwmMaterial", material)


class _Hook(QObject):
    """Application event filter: when a window is first shown, its title bar follows light/dark,
    a prepared window gets its material, and drop-down lists and tooltips get rounded corners."""

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Show and obj.isWidgetType() and obj.isWindow() and not obj.property("dwmDone"):
            obj.setProperty("dwmDone", True)
            _set(obj, DWMWA_USE_IMMERSIVE_DARK_MODE, int(_dark()))
            if obj.property("dwmMaterial"):
                # The whole client area becomes "frame", so DWM honours the window's alpha there and the
                # material shows wherever Qt paints nothing (otherwise transparent pixels turn black).
                margins = (ctypes.c_int * 4)(-1, -1, -1, -1)
                ctypes.windll.dwmapi.DwmExtendFrameIntoClientArea(ctypes.c_void_p(int(obj.winId())), margins)
                _set(obj, DWMWA_SYSTEMBACKDROP_TYPE, obj.property("dwmMaterial"))
            if obj.windowType() in (Qt.Popup, Qt.ToolTip):
                _set(obj, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUNDSMALL)
        return False


def install(app) -> bool:
    """Start applying materials to every window. Returns whether they are in use."""
    global _hook
    if _hook is not None:
        return True
    if not supported(app):
        return False
    _hook = _Hook()
    app.installEventFilter(_hook)
    return True


def refresh() -> None:
    """After a light/dark switch: Mica and the title bar follow the new theme."""
    if _hook is None:
        return
    for w in QApplication.topLevelWidgets():
        if w.property("dwmDone"):
            _set(w, DWMWA_USE_IMMERSIVE_DARK_MODE, int(_dark()))
