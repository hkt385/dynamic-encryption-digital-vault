from PySide6.QtWidgets import QTextBrowser, QVBoxLayout, QWidget

from paths import docs_dir

DOC_NAME = "DEVELOPER_INSTRUCTIONS.md"


class DeveloperPage(QWidget):
    """Shows docs/DEVELOPER_INSTRUCTIONS.md (the single source of truth, also readable on disk)."""

    def __init__(self):
        super().__init__()
        self.setObjectName("page")
        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(False)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.addWidget(self.browser)
        path = docs_dir() / DOC_NAME
        try:
            self.browser.setMarkdown(path.read_text(encoding="utf-8"))
        except OSError as e:
            self.browser.setPlainText(f"The developer documentation could not be loaded from {path}: "
                                      f"{e.strerror or e}")
