from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
                               QMessageBox, QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from models.file_metadata import format_size
from services.security_decision_service import CHOICE_REQUIRED, ERROR, UNSUPPORTED, SecurityDecision
from ui.high_critical_dialog import HighCriticalDialog
from ui.parameter_bar import ParameterBar
from ui.styles import LEVEL_COLORS, MUTED

COLUMNS = ("Name", "Type", "Size", "Predicted", "Final Level", "")
FINAL_PLACEHOLDER = {CHOICE_REQUIRED: "Choice required", UNSUPPORTED: "Not available", ERROR: "Error"}


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

        title = QLabel("Upload")
        title.setObjectName("title")
        self.select_btn = QPushButton("Select Files")
        self.select_btn.clicked.connect(self.select_files)
        self.predict_btn = QPushButton("Predict Security Level")
        self.predict_btn.clicked.connect(self.run_prediction)

        self.heading = QLabel("Selected Files")
        self.heading.setObjectName("sectionLabel")
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setFocusPolicy(Qt.NoFocus)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for i in range(1, len(COLUMNS)):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.status = QLabel()
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        self.store_btn = QPushButton("Encrypt")
        self.store_btn.setObjectName("primary")
        self.store_btn.clicked.connect(self.store)

        row = QHBoxLayout()
        row.addWidget(self.select_btn)
        row.addWidget(self.predict_btn)
        row.addStretch()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self.param_bar)            # parameters sit at the very top of this page
        body = QVBoxLayout()
        body.setContentsMargins(28, 24, 28, 24)
        body.setSpacing(14)
        lay.addLayout(body, 1)
        lay = body
        lay.addWidget(title)
        lay.addLayout(row)
        lay.addWidget(self.heading)
        lay.addWidget(self.table, 1)
        lay.addWidget(self.status)
        lay.addWidget(self.store_btn, 0)
        self._render()

    # ---- file selection ------------------------------------------------------------------
    def select_files(self):
        names, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        if not names:                       # cancelled
            return
        self.entries = [Entry(Path(n)) for n in names if Path(n).is_file()]
        skipped = len(names) - len(self.entries)
        self.status.setText(f"{skipped} item(s) skipped because they are not valid files." if skipped else "")
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
        messages: list[str] = []
        for r, e in enumerate(self.entries):
            try:
                size = format_size(e.path.stat().st_size)
            except OSError:
                size = "unavailable"
            d = e.decision
            if d is None:
                predicted, final = "Not predicted", ""
            else:
                predicted = d.predicted or "Error"
                final = d.level or FINAL_PLACEHOLDER.get(d.status, "Error")
                shown = ([d.message] if d.status in (UNSUPPORTED, ERROR) else []) + d.notes
                for m in shown:
                    m = f"{e.path.name}: {m}" if len(self.entries) > 1 else m
                    if m not in messages:
                        messages.append(m)
            cells = (e.path.name, (e.path.suffix.lstrip(".") or "file").upper(), size, predicted, final)
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c >= 3:
                    item.setForeground(QColor(LEVEL_COLORS.get(text, MUTED)))
                self.table.setItem(r, c, item)
            self.table.removeCellWidget(r, 5)
            if d is not None and d.status == CHOICE_REQUIRED:
                btn = QPushButton("Choose High/Critical")
                btn.clicked.connect(lambda _=False, en=e: self._reopen(en))
                self.table.setCellWidget(r, 5, btn)
        self.table.resizeRowsToContents()
        if messages:
            self.status.setText("\n".join(messages))
        elif has and all(e.decision is None for e in self.entries) and not self.status.text():
            self.status.setText("Choose the prediction parameters above, then predict.")
        self.store_btn.setEnabled(not self.runner.busy and
                                  any(e.decision and e.decision.is_final for e in self.entries))
        self.predict_btn.setEnabled(not self.runner.busy)

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
