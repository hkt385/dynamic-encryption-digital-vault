"""Windows 11 (Fluent) look for the whole app.

Colours follow the Windows light/dark setting (and switch live); the accent is the standard Windows
blue rather than the user's accent, which may be grey and would make the main button look disabled.
Sizes follow the Windows type ramp (14 px body, 12 px caption, 20 px subtitle, 28 px title) and
geometry (4 px control corners, 8 px for cards and the content layer). On Windows 11 the main window
sits on Mica and dialogs on Acrylic (ui/backdrop.py).

Motion uses the Fluent timings and curve, so the web version can reuse them as CSS
(`transition: opacity 167ms cubic-bezier(0, 0, 0, 1)`). Only opacity and position are animated,
never anything that re-lays out text, and nothing animates while idle.
"""
import ctypes
import sys

from PySide6.QtCore import QEasingCurve, QPointF, Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette

from ui import icons_rc  # noqa: F401  registers :/icons/ (chevrons drawn from Segoe Fluent Icons E70D/E70E;
                         # rebuild: pyside6-rcc dedv/ui/icons/icons.qrc -o dedv/ui/icons_rc.py)

THEMES = {
    "dark": dict(
        bg="#202020", layer="#272727", layer_mica="#4c3a3a3a", layer_stroke="#1c1c1c", card="#2b2b2b", card_stroke="#1d1d1d",
        control="#2d2d2d", control_hover="#323232", control_pressed="#272727", control_disabled="#262626",
        control_stroke="#353535", control_stroke_bottom="#2a2a2a", input_line="#9a9a9a",
        input_focus="#1f1f1f", subtle_hover="#2d2d2d", subtle_selected="#2d2d2d", divider="#353535",
        text="#ffffff", text2="#c5c5c5", text3="#9e9e9e", disabled="#717171",
        accent="#60cdff", accent_hover="#5bbdea", accent_pressed="#56a9d1", on_accent="#000000",
        accent_disabled="#434343", on_accent_disabled="#a7a7a7", selection="#0078d4",
        scroll="#9f9f9f", scrim=(0, 0, 0, 140), nav_fill=(255, 255, 255, 15), shadow=None,
        info_bg="#2b2b2b", info_stroke="#353535",
        success="#6ccb5f", success_bg="#393d1b", warning="#fce100", warning_bg="#433519",
        error="#ff99a4", error_bg="#442726",
        levels={"Low": "#8ac6e6", "Standard": "#6ccb5f", "Enhanced": "#e9c46a", "High": "#f4a261",
                "Critical": "#ff99a4", "High/Critical": "#ff99a4"},
    ),
    "light": dict(
        bg="#f3f3f3", layer="#f9f9f9", layer_mica="#80ffffff", layer_stroke="#e5e5e5", card="#ffffff", card_stroke="#e5e5e5",
        control="#fbfbfb", control_hover="#f6f6f6", control_pressed="#f2f2f2", control_disabled="#f5f5f5",
        control_stroke="#e3e3e3", control_stroke_bottom="#cdcdcd", input_line="#868686",
        input_focus="#ffffff", subtle_hover="#eaeaea", subtle_selected="#e6e6e6", divider="#e5e5e5",
        text="#1b1b1b", text2="#5f5f5f", text3="#8a8a8a", disabled="#a0a0a0",
        accent="#005fb8", accent_hover="#196cba", accent_pressed="#3380c4", on_accent="#ffffff",
        accent_disabled="#c5c5c5", on_accent_disabled="#ffffff", selection="#0078d4",
        scroll="#8a8a8a", scrim=(0, 0, 0, 80), nav_fill=(0, 0, 0, 10), shadow=(0, 0, 0, 2),
        info_bg="#ffffff", info_stroke="#e5e5e5",
        success="#0f7b0f", success_bg="#dff6dd", warning="#9d5d00", warning_bg="#fff4ce",
        error="#c42b1c", error_bg="#fde7e9",
        levels={"Low": "#1d6a99", "Standard": "#0f7b0f", "Enhanced": "#8a5a00", "High": "#b04a00",
                "Critical": "#c42b1c", "High/Critical": "#c42b1c"},
    ),
}

_theme = THEMES["dark"]
_hooked = False
_mica = False
_motion = False          # off until apply(): tests and --selftest run without animations

# Fluent motion ("Timing and easing", learn.microsoft.com): durations in ms and the
# "fast out, slow in" curve for anything entering or moving into place.
FASTER, FAST, NORMAL = 83, 167, 250
ENTER = (0.0, 0.0, 0.0, 1.0)            # CSS: cubic-bezier(0, 0, 0, 1)


def motion(ms: int) -> int:
    """Animation length, or 0 when Windows "Animation effects" is off (reduced motion)."""
    return ms if _motion else 0


def ease() -> QEasingCurve:
    c = QEasingCurve(QEasingCurve.BezierSpline)
    c.addCubicBezierSegment(QPointF(*ENTER[:2]), QPointF(*ENTER[2:]), QPointF(1, 1))
    return c


def _windows_animations() -> bool:
    if sys.platform != "win32":
        return True
    on = ctypes.c_int(1)
    ok = ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(on), 0)  # SPI_GETCLIENTAREAANIMATION
    return bool(on.value) if ok else True


def is_dark() -> bool:
    return _theme is THEMES["dark"]


def color(name: str) -> str:
    """A colour of the current theme, read at paint time so a theme switch is picked up."""
    return _theme[name]


def level_color(level: str) -> str:
    return _theme["levels"].get(level, _theme["text2"])


def _family(*names: str) -> str:
    families = set(QFontDatabase.families())
    return next((n for n in names if n in families), names[-1])


def icon_family() -> str:
    """Windows 11 icon font; Windows 10 has the same glyphs in Segoe MDL2 Assets."""
    return _family("Segoe Fluent Icons", "Segoe MDL2 Assets")


def _palette(t: dict) -> QPalette:
    p = QPalette()
    for role, key in ((QPalette.Window, "bg"), (QPalette.WindowText, "text"), (QPalette.Base, "control"),
                      (QPalette.AlternateBase, "card"), (QPalette.Text, "text"), (QPalette.Button, "control"),
                      (QPalette.ButtonText, "text"), (QPalette.ToolTipBase, "card"), (QPalette.ToolTipText, "text"),
                      (QPalette.PlaceholderText, "text3"), (QPalette.Highlight, "selection"),
                      (QPalette.Link, "accent"), (QPalette.Accent, "accent"), (QPalette.Light, "control_hover"),
                      (QPalette.Midlight, "control_stroke"), (QPalette.Mid, "control_stroke"),
                      (QPalette.Dark, "control_stroke_bottom"), (QPalette.Shadow, "layer_stroke")):
        p.setColor(role, QColor(t[key]))
    p.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        p.setColor(QPalette.Disabled, role, QColor(t["disabled"]))
    return p


def _stylesheet(t: dict, name: str, display: str, small: str, icons: str) -> str:
    return f"""
QMainWindow, QDialog, QMessageBox {{ background: {t['bg']}; }}
*[backdrop="true"] {{ background: transparent; }}   /* windows on Mica / Acrylic (ui/backdrop.py) */
QWidget#page, QWidget#root {{ background: transparent; }}
QWidget#content {{
    background: {t['layer_mica'] if _mica else t['layer']}; border: 1px solid {t['layer_stroke']};
    border-right: none; border-bottom: none; border-top-left-radius: 8px;
}}
QWidget#navPill {{ background: {t['accent']}; border-radius: 1px; }}
QLabel {{ background: transparent; }}
QLabel#muted {{ color: {t['text2']}; }}
QLabel#caption {{ color: {t['text2']}; font-family: "{small}"; font-size: 12px; }}
QLabel#section {{ font-weight: 600; }}
QLabel#subtitle {{ font-family: "{display}"; font-size: 20px; font-weight: 600; }}
QLabel#title {{ font-family: "{display}"; font-size: 28px; font-weight: 600; }}
QDialog QLabel#title {{ font-size: 20px; }}
QLabel#error {{ color: {t['error']}; }}
QToolTip {{
    background: {t['card']}; color: {t['text']}; border: 1px solid {t['control_stroke']};
    border-radius: 4px; padding: 4px 8px;
}}

/* Side bar */
QFrame#navPane {{ background: transparent; }}
QLabel#avatar {{
    background: {t['accent']}; color: {t['on_accent']}; border-radius: 18px;
    font-family: "{display}"; font-size: 16px; font-weight: 600;
}}
QLabel#accountName {{ font-weight: 600; }}
QLabel#accountPath {{ color: {t['text2']}; font-family: "{small}"; font-size: 12px; }}
QPushButton#nav {{ background: transparent; border: none; min-height: 36px; padding: 0 12px 0 44px; }}

/* Buttons */
QPushButton {{
    background: {t['control']}; color: {t['text']}; border: 1px solid {t['control_stroke']};
    border-bottom-color: {t['control_stroke_bottom']}; border-radius: 4px; padding: 5px 14px; min-height: 20px;
}}
QPushButton:hover {{ background: {t['control_hover']}; }}
QPushButton:pressed {{ background: {t['control_pressed']}; color: {t['text2']}; }}
QPushButton:focus {{ border-color: {t['text2']}; }}
QPushButton:disabled {{ background: {t['control_disabled']}; color: {t['disabled']}; border-color: {t['control_stroke']}; }}
QPushButton#primary {{ background: {t['accent']}; color: {t['on_accent']}; border: 1px solid {t['accent']}; }}
QPushButton#primary:hover {{ background: {t['accent_hover']}; border-color: {t['accent_hover']}; }}
QPushButton#primary:pressed {{ background: {t['accent_pressed']}; border-color: {t['accent_pressed']}; }}
QPushButton#primary:focus {{ border-color: {t['text']}; }}
QPushButton#primary:disabled {{
    background: {t['accent_disabled']}; border-color: {t['accent_disabled']}; color: {t['on_accent_disabled']};
}}
QPushButton#option {{ text-align: left; padding: 12px 16px; border-radius: 8px; }}

/* Text boxes and drop-downs */
QLineEdit, QComboBox, QSpinBox {{
    background: {t['control']}; color: {t['text']}; border: 1px solid {t['control_stroke']};
    border-bottom: 1px solid {t['input_line']}; border-radius: 4px; padding: 5px 10px; min-height: 20px;
    selection-background-color: {t['selection']}; selection-color: #ffffff;
}}
QComboBox {{ border-bottom-color: {t['control_stroke_bottom']}; }}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover {{ background: {t['control_hover']}; }}
QLineEdit:focus, QSpinBox:focus {{
    background: {t['input_focus']}; border-bottom: 2px solid {t['accent']}; padding-bottom: 4px;
}}
QComboBox:focus {{ border-color: {t['text2']}; }}
QLineEdit:read-only {{ color: {t['text2']}; background: {t['control_disabled']}; border-bottom-color: {t['control_stroke']}; }}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{ color: {t['disabled']}; background: {t['control_disabled']}; }}
QComboBox::drop-down {{ border: none; background: transparent; width: 30px; }}
QComboBox::down-arrow, QSpinBox::down-arrow {{ image: url(:/icons/chevron-down-{name}.png); width: 12px; height: 12px; }}
QSpinBox::up-arrow {{ image: url(:/icons/chevron-up-{name}.png); width: 12px; height: 12px; }}
QSpinBox::up-button, QSpinBox::down-button {{ border: none; background: transparent; width: 26px; }}QComboBox QAbstractItemView {{
    background: {t['card']}; color: {t['text']}; border: 1px solid {t['control_stroke']}; padding: 4px;
    outline: 0; selection-background-color: {t['subtle_selected']}; selection-color: {t['text']};
}}
QCheckBox {{ spacing: 8px; }}

/* Cards, message bars, tables */
QFrame#card {{ background: {t['card']}; border: 1px solid {t['card_stroke']}; border-radius: 8px; }}
QFrame#card QLabel {{ border: none; }}
QLabel#detailsCard {{
    background: {t['card']}; border: 1px solid {t['card_stroke']}; border-radius: 8px; padding: 12px 16px;
}}
QWidget#overlayCard {{ background: {t['card']}; border: 1px solid {t['control_stroke']}; border-radius: 8px; }}
QFrame#infoBar {{ background: {t['info_bg']}; border: 1px solid {t['info_stroke']}; border-radius: 4px; }}
QFrame#infoBar[severity="success"] {{ background: {t['success_bg']}; border-color: {t['success_bg']}; }}
QFrame#infoBar[severity="warning"] {{ background: {t['warning_bg']}; border-color: {t['warning_bg']}; }}
QFrame#infoBar[severity="error"] {{ background: {t['error_bg']}; border-color: {t['error_bg']}; }}
QLabel#infoIcon {{ font-family: "{icons}"; font-size: 16px; color: {t['accent']}; }}
QFrame#infoBar[severity="success"] QLabel#infoIcon {{ color: {t['success']}; }}
QFrame#infoBar[severity="warning"] QLabel#infoIcon {{ color: {t['warning']}; }}
QFrame#infoBar[severity="error"] QLabel#infoIcon {{ color: {t['error']}; }}

QTableWidget {{
    background: {t['card']}; border: 1px solid {t['card_stroke']}; border-radius: 8px;
    gridline-color: transparent; outline: 0;
    selection-background-color: {t['subtle_selected']}; selection-color: {t['text']};
}}
QTableWidget::item {{ padding: 0 12px; border: none; }}
QTableWidget::item:selected {{ background: {t['subtle_selected']}; }}
QHeaderView {{ background: transparent; border: none; }}
QHeaderView::section {{
    background: transparent; color: {t['text2']}; border: none; border-bottom: 1px solid {t['divider']};
    padding: 8px 12px; font-family: "{small}"; font-size: 12px;
}}
QTableCornerButton::section {{ background: transparent; border: none; }}
QTableWidget QComboBox {{ padding: 2px 8px; min-height: 18px; margin: 6px 8px 6px 0; }}
QTableWidget QPushButton {{ padding: 2px 10px; min-height: 18px; margin: 6px 8px 6px 0; }}
QTextBrowser, QPlainTextEdit {{
    background: {t['card']}; color: {t['text']}; border: 1px solid {t['card_stroke']}; border-radius: 8px;
    padding: 8px; selection-background-color: {t['selection']}; selection-color: #ffffff;
}}
QGraphicsView {{ background: {t['layer']}; border: 1px solid {t['card_stroke']}; border-radius: 8px; }}

/* Thin Windows 11 scroll bars */
QScrollBar:vertical {{ background: transparent; width: 12px; margin: 2px 0; }}
QScrollBar:horizontal {{ background: transparent; height: 12px; margin: 0 2px; }}
QScrollBar::handle:vertical {{ background: {t['scroll']}; border-radius: 3px; min-height: 32px; margin: 0 3px; }}
QScrollBar::handle:horizontal {{ background: {t['scroll']}; border-radius: 3px; min-width: 32px; margin: 3px 0; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
"""


def apply(app) -> None:
    """Theme the whole application from the Windows light/dark setting; re-applied when it changes."""
    global _theme, _hooked, _mica, _motion
    from ui import backdrop
    hints = app.styleHints()
    name = "dark" if hints.colorScheme() == Qt.ColorScheme.Dark else "light"
    _theme = THEMES[name]
    _motion = _windows_animations()
    if not _hooked:
        app.setStyle("Fusion")
        _mica = backdrop.install(app)            # Windows 11 22H2+ only; solid colours otherwise
    font = QFont(_family("Segoe UI Variable Text", "Segoe UI"))
    font.setPixelSize(14)
    app.setFont(font)
    app.setPalette(_palette(_theme))
    app.setStyleSheet(_stylesheet(_theme, name, _family("Segoe UI Variable Display", "Segoe UI"),
                                  _family("Segoe UI Variable Small", "Segoe UI"), icon_family()))
    backdrop.refresh()                           # light/dark Mica and title bars of open windows
    if not _hooked:
        hints.colorSchemeChanged.connect(lambda _scheme: apply(app))
        _hooked = True
