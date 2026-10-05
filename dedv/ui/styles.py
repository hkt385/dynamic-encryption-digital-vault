BG = "#1a1c20"
SIDEBAR = "#212429"
PANEL = "#25282e"
BORDER = "#33373e"
TEXT = "#e6e8eb"
MUTED = "#8a9099"
ACCENT = "#5b9bd5"
ACCENT_HOVER = "#74aee0"

# Subtle security-level tints (text colour only)
LEVEL_COLORS = {
    "Unassigned": "#8a9099",
    "Standard": "#7fb77e",
    "Enhanced": "#d6b25e",
    "High/Critical": "#d9776f",
}

STYLESHEET = f"""
* {{ font-family: "Segoe UI"; font-size: 10pt; color: {TEXT}; }}
QMainWindow, QDialog, QWidget#page, QWidget#root {{ background: {BG}; }}
QLabel {{ background: transparent; }}
QLabel#muted, QLabel#sectionLabel {{ color: {MUTED}; }}
QLabel#sectionLabel {{ font-size: 8pt; font-weight: 600; letter-spacing: 1px; }}
QLabel#title {{ font-size: 16pt; font-weight: 600; }}
QLabel#brand {{ font-size: 15pt; font-weight: 700; color: {ACCENT}; }}

QFrame#sidebar {{ background: {SIDEBAR}; border-right: 1px solid {BORDER}; }}
QFrame#topbar {{ background: {BG}; border-bottom: 1px solid {BORDER}; }}

QPushButton#nav {{
    background: transparent; border: none; border-radius: 6px;
    padding: 10px 14px; text-align: left; color: {MUTED};
}}
QPushButton#nav:hover {{ background: {PANEL}; color: {TEXT}; }}
QPushButton#nav:checked {{ background: {PANEL}; color: {TEXT}; border-left: 3px solid {ACCENT}; }}

QPushButton {{
    background: {PANEL}; border: 1px solid {BORDER}; border-radius: 6px; padding: 8px 16px;
}}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:disabled {{ color: {MUTED}; }}
QPushButton#primary {{ background: {ACCENT}; border: none; color: #101318; font-weight: 600; }}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#primary:disabled {{ background: {BORDER}; color: {MUTED}; }}

QLineEdit, QComboBox {{
    background: {PANEL}; border: 1px solid {BORDER}; border-radius: 6px; padding: 7px 10px;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QLineEdit:read-only {{ color: {MUTED}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: {PANEL}; border: 1px solid {BORDER}; selection-background-color: {BORDER};
}}

QTableWidget {{
    background: {BG}; border: 1px solid {BORDER}; border-radius: 6px;
    gridline-color: transparent; outline: 0; alternate-background-color: #1e2024;
}}
QTableWidget::item {{ padding: 6px 10px; border: none; }}
QTableWidget::item:selected {{ background: {PANEL}; }}
QHeaderView::section {{
    background: {SIDEBAR}; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER};
    padding: 8px 10px; font-weight: 600;
}}
QScrollBar:vertical {{ background: transparent; width: 10px; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 5px; min-height: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QMessageBox {{ background: {BG}; }}
"""
