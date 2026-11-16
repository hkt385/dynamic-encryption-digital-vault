from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from services.security_decision_service import HIGH_CRITICAL_OPTIONS


class HighCriticalDialog(QDialog):
    """Enterprise-only: pick High or Critical for one file. Closing/Escape leaves `choice` None."""

    def __init__(self, file_name: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Choose security level")
        self.setModal(True)
        self.setMinimumWidth(520)
        self.choice: str | None = None

        title = QLabel("High/Critical predicted")
        title.setObjectName("title")
        intro = QLabel(f"The model predicts High/Critical for <b>{file_name}</b>. "
                       "Choose the level to use for this file.")
        intro.setWordWrap(True)
        note = QLabel("These describe the intended configuration only; "
                      "no encryption is chosen or applied by this selection.")
        note.setObjectName("muted")
        note.setWordWrap(True)

        row = QHBoxLayout()
        self.buttons: dict[str, QPushButton] = {}
        for level, (storage, config) in HIGH_CRITICAL_OPTIONS.items():
            btn = QPushButton(f"{level}\n{storage}\n{config}")
            btn.setMinimumHeight(90)
            btn.clicked.connect(lambda _=False, lv=level: self._pick(lv))
            row.addWidget(btn)
            self.buttons[level] = btn
        later = QPushButton("Decide later")
        later.clicked.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(10)
        lay.addWidget(title)
        lay.addWidget(intro)
        lay.addLayout(row)
        lay.addWidget(note)
        lay.addWidget(later)

    def _pick(self, level: str):
        self.choice = level
        self.accept()
