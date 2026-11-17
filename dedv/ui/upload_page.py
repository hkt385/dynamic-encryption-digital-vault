from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QHBoxLayout,
                               QHeaderView, QLabel, QMessageBox, QPushButton, QTableWidget,
                               QTableWidgetItem, QWidget)

from models.file_metadata import format_size
from services.security_decision_service import (CHOICE_REQUIRED, ERROR, UNSUPPORTED, SecurityDecision,
                                                account_levels, floor_level, is_below)
from ui.high_critical_dialog import HighCriticalDialog
from ui.parameter_bar import ParameterBar
from ui.styles import level_color
from ui.widgets import InfoBar, page_layout

COLUMNS = ("Name", "Type", "Size", "Predicted", "Confidence", "Final level", "")
FINAL_COLUMN, ACTION_COLUMN = 5, 6
FINAL_PLACEHOLDER = {CHOICE_REQUIRED: "Choice required", UNSUPPORTED: "Not available", ERROR: "Error"}


def fill_levels(combo: QComboBox, levels, floor: str | None, why: str, label=str) -> None:
    """Add `levels` (item data = level); those below `floor` are disabled with `why` as tooltip."""
    for level in levels:
        combo.addItem(label(level), level)
        if is_below(level, floor):
            i = combo.count() - 1
            combo.model().item(i).setEnabled(False)
            combo.setItemData(i, why, Qt.ToolTipRole)


@dataclass
class Entry:
    path: Path
    decision: SecurityDecision | None = None
    prompted: bool = False        # the High/Critical dialog was already shown for this prediction


class UploadPage(QWidget):
    stored = Signal()

    def __init__(self, get_vault, config, engine, runner):
        """The prediction parameters live only on this page; `runner` is the shared TaskRunner."""
        super().__init__()
        self.setObjectName("page")
        self._get_vault = get_vault
        self.config = config
        self.engine = engine
        self.runner = runner
        self.param_bar = ParameterBar(config, engine.model, engine.load_error)
        self.param_bar.changed.connect(self.invalidate)
        self.entries: list[Entry] = []
        self._dialog_open = False

        self.select_btn = QPushButton("Select files")
        self.select_btn.clicked.connect(self.select_files)
        self.predict_btn = QPushButton("Predict security level")
        self.predict_btn.clicked.connect(self.run_prediction)

        self.heading = QLabel("Selected files")
        self.heading.setObjectName("section")
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(44)
        self.table.setFocusPolicy(Qt.NoFocus)
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for i in range(1, len(COLUMNS)):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(FINAL_COLUMN, QHeaderView.Fixed)     # sized for the level drop-down,
        header.resizeSection(FINAL_COLUMN, 150)                          # which contents-sizing cuts off
        self.probabilities = QLabel()
        self.probabilities.setObjectName("caption")
        self.probabilities.setWordWrap(True)
        self.status = InfoBar()
        self.ack = QCheckBox("I have reviewed this prediction and accept the final level.")
        self.ack.clicked.connect(self._acknowledge)      # clicked: not emitted by setChecked()
        self.store_btn = QPushButton("Encrypt")
        self.store_btn.setObjectName("primary")
        self.store_btn.setMinimumWidth(120)
        self.store_btn.clicked.connect(self.store)

        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(self.select_btn)
        row.addWidget(self.predict_btn)
        row.addStretch()
        bottom = QHBoxLayout()
        bottom.addWidget(self.ack)
        bottom.addStretch()
        bottom.addWidget(self.store_btn)

        lay, _ = page_layout(self, "Upload", "Encrypt new files into the vault.")
        lay.addWidget(self.param_bar)            # the answers come first: they decide the level
        lay.addLayout(row)
        lay.addWidget(self.heading)
        lay.addWidget(self.table, 1)
        lay.addWidget(self.probabilities)
        lay.addWidget(self.status)
        lay.addLayout(bottom)
        self._render()

    # ---- file selection ------------------------------------------------------------------
    def select_files(self):
        names, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        if not names:                       # cancelled
            return
        self.entries = [Entry(Path(n)) for n in names if Path(n).is_file()]
        skipped = len(names) - len(self.entries)
        self.status.setText(f"{skipped} item(s) skipped because they are not valid files." if skipped else "",
                            "warning")
        self._render()

    # ---- prediction ----------------------------------------------------------------------
    def invalidate(self):
        """Parameters or account type changed: earlier predictions no longer apply."""
        if any(e.decision for e in self.entries):
            for e in self.entries:
                e.decision, e.prompted = None, False
            self.status.setText("Parameters or account type changed. Predict again.")
            self._render()

    def run_prediction(self):
        if not self.entries:
            return
        self.status.setText("")
        account, params = self.config.get("account_type"), self.param_bar.values()
        for e in self.entries:
            e.decision, e.prompted = self.engine.decide(e.path, account, params), False
        self._render()
        self._prompt_pending()

    def _prompt_pending(self):
        """Show the High/Critical dialog once per pending file (never twice for one prediction)."""
        if self._dialog_open:
            return
        self._dialog_open = True
        try:
            for e in self.entries:
                if e.decision and e.decision.status == CHOICE_REQUIRED and not e.prompted:
                    e.prompted = True
                    self._ask_choice(e)
        finally:
            self._dialog_open = False
        self._render()

    def _ask_choice(self, entry: Entry):
        dlg = HighCriticalDialog(entry.path.name, self)
        if dlg.exec() == HighCriticalDialog.Accepted and dlg.choice:
            entry.decision.choose_high_critical(dlg.choice)
        # Dismissed: stays CHOICE_REQUIRED and nothing is assigned; the row button reopens it.

    def _reopen(self, entry: Entry):
        if self._dialog_open or entry not in self.entries:
            return
        self._dialog_open = True
        try:
            self._ask_choice(entry)
        finally:
            self._dialog_open = False
        self._render()

    # ---- display -------------------------------------------------------------------------
    def _render(self):
        has = bool(self.entries)
        for w in (self.heading, self.table, self.store_btn, self.predict_btn):
            w.setVisible(has)
        self.table.setRowCount(len(self.entries))
        messages: dict[str, list[str]] = {}          # message -> names of the files it applies to
        severity = "warning"
        for r, e in enumerate(self.entries):
            try:
                size = format_size(e.path.stat().st_size)
            except OSError:
                size = "unavailable"
            d = e.decision
            if d is None:
                predicted, confidence, final = "Not predicted", "", ""
            else:
                predicted = d.predicted or "Error"
                confidence = f"{d.confidence:.0%}" if d.confidence is not None else ""
                final = "" if d.is_final else FINAL_PLACEHOLDER.get(d.status, "Error")   # combo below
                blocked = d.status in (UNSUPPORTED, ERROR)
                if blocked:
                    severity = "error"
                for m in ([d.message] if blocked else []) + d.notes:
                    messages.setdefault(m, []).append(e.path.name)
            cells = (e.path.name, (e.path.suffix.lstrip(".") or "file").upper(), size, predicted,
                     confidence, final)
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c in (3, FINAL_COLUMN):
                    item.setForeground(QColor(level_color(text)))
                self.table.setItem(r, c, item)
            for c in (FINAL_COLUMN, ACTION_COLUMN):
                self.table.removeCellWidget(r, c)
            if d is not None and d.is_final:
                combo = QComboBox()
                fill_levels(combo, account_levels(d.account_type), floor_level(d.predicted),
                            f"Below the predicted level {d.predicted}. "
                            "The level may be raised but not lowered.")
                combo.setCurrentIndex(combo.findData(d.level))
                combo.activated.connect(lambda i, en=e, cb=combo: self._set_level(en, cb))
                self.table.setCellWidget(r, FINAL_COLUMN, combo)
            if d is not None and d.status == CHOICE_REQUIRED:
                btn = QPushButton("Choose High/Critical")
                btn.clicked.connect(lambda _=False, en=e: self._reopen(en))
                self.table.setCellWidget(r, ACTION_COLUMN, btn)
        self.table.resizeRowsToContents()
        # The model never sees the file, so every file in a batch has the same probabilities.
        probs = next((e.decision.probabilities for e in self.entries
                      if e.decision and e.decision.probabilities), None)
        self.probabilities.setText("Model probabilities: " + ", ".join(
            f"{label} {p:.0%}" for label, p in probs.items()) if probs else "")
        self.probabilities.setVisible(bool(probs))
        if messages:
            # The model never sees the file, so a message usually applies to every file: say it once.
            lines = [m if len(names) == len(self.entries) else f"{', '.join(names)}: {m}"
                     for m, names in messages.items()]
            self.status.setText("\n".join(f"• {m}" for m in lines) if len(lines) > 1 else lines[0], severity)
        elif has and all(e.decision is None for e in self.entries) and not self.status.text():
            self.status.setText("Answer the questions above, then select Predict security level.")
        self._update_actions()

    def _needing_ack(self) -> list[SecurityDecision]:
        return [e.decision for e in self.entries
                if e.decision and e.decision.is_final and e.decision.needs_ack]

    def _update_actions(self):
        need = self._needing_ack()
        acked = all(d.acknowledged for d in need)
        self.ack.setVisible(bool(need))
        self.ack.setChecked(bool(need) and acked)
        self.store_btn.setEnabled(not self.runner.busy and acked and
                                  any(e.decision and e.decision.is_final for e in self.entries))
        self.predict_btn.setEnabled(not self.runner.busy)

    def _acknowledge(self, checked: bool):
        for d in self._needing_ack():
            d.acknowledged = checked
        self._update_actions()

    def _set_level(self, entry: Entry, combo: QComboBox):
        """Not re-rendered here: the combo emitting this signal must stay alive."""
        try:
            entry.decision.raise_level(combo.currentData())
        except ValueError as e:              # disabled items cannot be picked; this is the backstop
            combo.setCurrentIndex(combo.findData(entry.decision.level))
            self.status.setText(str(e), "warning")

    # ---- encrypting ----------------------------------------------------------------------
    def store(self):
        vault = self._get_vault()
        if not vault or not self.entries or self.runner.busy:
            return
        account = self._get_account_type()
        batch = [(e.path, e.decision) for e in self.entries if e.decision is not None]
        not_predicted = [(e.path.name, "Not predicted yet.") for e in self.entries if e.decision is None]

        def work():
            stored, failed, done_paths = [], list(not_predicted), []
            for path, decision in batch:        # one at a time so a failure never hides earlier results
                res = vault.store_files([(path, decision)], account)
                stored += res.stored
                failed += res.failed
                if res.stored:
                    done_paths.append(path)
            return stored, failed, done_paths

        self.store_btn.setEnabled(False)
        self.predict_btn.setEnabled(False)
        if not self.runner.run(work, self._store_done, self._store_failed):
            self._render()

    def _store_done(self, result):
        stored, failed, done_paths = result
        # Reported only now: encryption, key storage and the metadata update have all completed.
        self.entries = [e for e in self.entries if e.path not in done_paths]
        msg = []
        if stored:
            msg.append(f"{len(stored)} file(s) encrypted and stored.")
        if failed:
            msg.append("Could not store:" + "\n" + "\n".join(f"• {n}: {why}" for n, why in failed))
        self.status.setText("")
        self._render()
        box = QMessageBox.warning if failed else QMessageBox.information
        box(self, "Encrypt", "\n\n".join(msg))
        if stored:
            self.stored.emit()

    def _store_failed(self, message: str):
        self._render()
        QMessageBox.critical(self, "Encrypt", f"Encryption failed: {message}")

    def _get_account_type(self):
        return self.config.get("account_type")
