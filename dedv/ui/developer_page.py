from PySide6.QtWidgets import (QHBoxLayout, QLabel, QMessageBox, QPushButton, QTextBrowser,
                               QVBoxLayout, QWidget)

from paths import docs_dir
from services import migration_service
from services.storage_service import StorageError

DOC_NAME = "DEVELOPER_INSTRUCTIONS.md"


class DeveloperPage(QWidget):
    """Audit-log check, the leftover DEDV 0.1 key file, and docs/DEVELOPER_INSTRUCTIONS.md
    (the single source of truth, also readable on disk)."""

    def __init__(self, get_vault=lambda: None):
        super().__init__()
        self.setObjectName("page")
        self._get_vault = get_vault

        self.verify_btn = QPushButton("Verify audit log")
        self.verify_btn.clicked.connect(self.verify_audit_log)
        self.audit_result = QLabel()
        self.audit_result.setObjectName("muted")
        row = QHBoxLayout()
        row.addWidget(self.verify_btn)
        row.addWidget(self.audit_result, 1)

        self.old_key_note = QLabel()
        self.old_key_note.setWordWrap(True)
        self.old_key_btn = QPushButton("Delete old key file")
        self.old_key_btn.clicked.connect(self.delete_old_key_file)
        key_row = QHBoxLayout()
        key_row.addWidget(self.old_key_note, 1)
        key_row.addWidget(self.old_key_btn)

        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(False)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.addLayout(row)
        lay.addLayout(key_row)
        lay.addWidget(self.browser)
        path = docs_dir() / DOC_NAME
        try:
            self.browser.setMarkdown(path.read_text(encoding="utf-8"))
        except OSError as e:
            self.browser.setPlainText(f"The developer documentation could not be loaded from {path}: "
                                      f"{e.strerror or e}")
        self.refresh()

    def refresh(self):
        self.verify_btn.setEnabled(self._get_vault() is not None)
        key_file = migration_service.old_key_file()
        present = key_file.exists()
        self.old_key_note.setVisible(present)
        self.old_key_btn.setVisible(present)
        if present:
            self.old_key_note.setText(
                f"Warning: the plain-text key file of DEDV 0.1 still exists: {key_file}. Upgraded vaults "
                "no longer use it. Delete it once every old vault has been upgraded.")

    def verify_audit_log(self):
        vault = self._get_vault()
        if vault is None:
            return
        try:
            ok, count, bad_id = vault.audit.verify()
        except StorageError as e:
            self.audit_result.setText(str(e))
            return
        self.audit_result.setText(f"Audit log intact: {count} entries, hash chain verified." if ok else
                                  f"AUDIT LOG DAMAGED: the hash chain breaks at entry {bad_id} of {count}. "
                                  "Entries from there on were changed, inserted or removed.")

    def delete_old_key_file(self):
        key_file = migration_service.old_key_file()
        if QMessageBox.question(
                self, "Delete the old key file?",
                f"Overwrite and delete {key_file}?\n\nAny DEDV vault that has NOT been upgraded yet shares "
                "this file and could never be opened again without it.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        try:
            migration_service.delete_old_key_file()
        except OSError as e:
            QMessageBox.warning(self, "Old key file", f"The file could not be deleted: {e.strerror or e}")
            return
        vault = self._get_vault()
        if vault is not None:
            vault.audit.append("old_key_file_deleted")
        self.refresh()
