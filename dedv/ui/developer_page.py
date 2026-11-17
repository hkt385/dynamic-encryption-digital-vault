from PySide6.QtWidgets import QHBoxLayout, QMessageBox, QPushButton, QTextBrowser, QWidget

from paths import docs_dir
from services import migration_service
from services.storage_service import StorageError
from ui.widgets import InfoBar, elevate, page_layout

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
        self.audit_result = InfoBar()
        self.old_key_note = InfoBar()
        self.old_key_btn = QPushButton("Delete old key file")
        self.old_key_btn.clicked.connect(self.delete_old_key_file)
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(self.verify_btn)
        row.addWidget(self.old_key_btn)
        row.addStretch()

        self.browser = elevate(QTextBrowser())
        self.browser.setOpenExternalLinks(False)
        lay, _ = page_layout(self, "Developer", "Check the audit log and read how DEDV is built.")
        lay.addLayout(row)
        lay.addWidget(self.audit_result)
        lay.addWidget(self.old_key_note)
        lay.addWidget(self.browser, 1)
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
                f"The plain-text key file of DEDV 0.1 still exists: {key_file}. Upgraded vaults "
                "no longer use it. Delete it once every old vault has been upgraded.", "warning")

    def verify_audit_log(self):
        vault = self._get_vault()
        if vault is None:
            return
        try:
            ok, count, bad_id = vault.audit.verify()
        except StorageError as e:
            self.audit_result.setText(str(e), "error")
            return
        if ok:
            self.audit_result.setText(f"Audit log intact: {count} entries, hash chain verified.", "success")
        else:
            self.audit_result.setText(f"Audit log damaged: the hash chain breaks at entry {bad_id} of {count}. "
                                      "Entries from there on were changed, inserted or removed.", "error")

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
