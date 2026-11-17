from PySide6.QtCore import Signal
from PySide6.QtWidgets import QComboBox, QFrame, QGridLayout, QLabel, QVBoxLayout

from config.config_manager import ConfigError, ConfigManager
from services.ml_model_service import FEATURES, MLModelService


class ParameterBar(QFrame):
    r"""Model-input dropdowns ("About these files" card on the Upload page). Options come from the model.

    Selections are saved to the application settings file (%APPDATA%\DEDV\settings.json)
    on every user change and validated when restored. The bar lives outside the page stack,
    so navigating or refreshing pages never rebuilds or resets it.
    """
    changed = Signal()

    def __init__(self, config: ConfigManager, model: MLModelService | None, load_error: str = ""):
        super().__init__()
        self.setObjectName("card")
        self.config = config
        self.model = model
        self.combos: dict[str, QComboBox] = {}
        self.status = QLabel()
        self.status.setObjectName("error")
        self.status.setWordWrap(True)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 16)
        lay.setSpacing(4)
        head = QLabel("About these files")
        head.setObjectName("section")
        hint = QLabel("Your answers decide the security level. DEDV does not read the files to decide.")
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        lay.addWidget(head)
        lay.addWidget(hint)
        lay.addSpacing(8)
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)
        lay.addLayout(grid)
        lay.addWidget(self.status)
        self.status.hide()                      # shown only for an error

        if model is None:
            self._error(f"Prediction model unavailable: {load_error}")
            return
        saved = self.config.get_model_parameters()
        defaults = model.default_parameters()
        per_row = 4
        for i, f in enumerate(FEATURES):
            cb = QComboBox()
            cb.addItems(model.options(f))
            v = saved.get(f)
            cb.setCurrentText(v if isinstance(v, str) and v in model.options(f) else defaults[f])
            cb.activated.connect(self._on_user_change)       # user picks only, never programmatic
            label = QLabel(f)
            r, c = divmod(i, per_row)
            grid.addWidget(label, r * 2, c)
            grid.addWidget(cb, r * 2 + 1, c)
            grid.setColumnStretch(c, 1)
            self.combos[f] = cb
        self._persist()      # writes defaults on first launch / repairs unsupported saved values

    def values(self) -> dict[str, str]:
        return {f: cb.currentText() for f, cb in self.combos.items()}

    def _persist(self) -> bool:
        try:
            self.config.update(model_parameters=self.values())
        except ConfigError as e:
            self._error(f"Selections could not be saved: {e}")
            return False
        self._error("")
        return True

    def _error(self, text: str):
        self.status.setText(text)
        self.status.setVisible(bool(text))

    def _on_user_change(self, _index: int = 0):
        self._persist()
        self.changed.emit()
