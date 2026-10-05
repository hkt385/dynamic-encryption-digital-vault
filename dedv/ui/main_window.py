from pathlib import Path

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import (QButtonGroup, QFrame, QHBoxLayout, QLabel, QMainWindow,
                               QMessageBox, QPushButton, QStackedWidget, QVBoxLayout, QWidget)

from config.config_manager import ConfigManager
from services.storage_service import StorageError, create_vault
from services.vault_service import VaultService
from ui.settings_page import SettingsPage
from ui.upload_page import UploadPage
from ui.view_page import ViewPage


class MainWindow(QMainWindow):
    def __init__(self, config: ConfigManager):
        super().__init__()
        self.config = config
        self.vault: VaultService | None = None
        self.setWindowTitle("Dynamic Encryption Digital Vault")
        self.setMinimumSize(1200, 700)

        self._settings = QSettings("DEDV", "DEDV")
        geo = self._settings.value("geometry")
        if geo:
            self.restoreGeometry(geo)

        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(180)
        sl = QVBoxLayout(sidebar)
        sl.setContentsMargins(12, 20, 12, 16)
        sl.setSpacing(4)
        brand = QLabel("DEDV")
        brand.setObjectName("brand")
        sl.addWidget(brand)
        sl.addSpacing(18)

        # Pages
        self.view_page = ViewPage(lambda: self.vault)
        self.upload_page = UploadPage(lambda: self.vault, lambda: self.config.get("account_type"))
        self.settings_page = SettingsPage(config, self.change_directory)
        self.upload_page.stored.connect(self.view_page.refresh)
        self.settings_page.changed.connect(self._update_topbar)
        self.stack = QStackedWidget()

        group = QButtonGroup(self)
        group.setExclusive(True)
        for i, (label, page) in enumerate((("View", self.view_page), ("Upload", self.upload_page),
                                           ("Settings", self.settings_page))):
            self.stack.addWidget(page)
            b = QPushButton(label)
            b.setObjectName("nav")
            b.setCheckable(True)
            group.addButton(b, i)
            sl.addWidget(b)
            if i == 0:
                b.setChecked(True)
        group.idClicked.connect(self._navigate)
        sl.addStretch()

        # Top bar
        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar.setFixedHeight(52)
        tl = QHBoxLayout(topbar)
        tl.setContentsMargins(28, 0, 28, 0)
        self.user_label = QLabel()
        self.path_label = QLabel()
        self.path_label.setObjectName("muted")
        tl.addWidget(self.user_label)
        tl.addStretch()
        tl.addWidget(self.path_label)

        right = QWidget()
        right.setObjectName("root")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)
        rl.addWidget(topbar)
        rl.addWidget(self.stack, 1)

        central = QWidget()
        central.setObjectName("root")
        cl = QHBoxLayout(central)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        cl.addWidget(sidebar)
        cl.addWidget(right, 1)
        self.setCentralWidget(central)

        self.load_vault()

    def load_vault(self):
        """(Re)open the vault from configuration and refresh every page."""
        try:
            self.vault = VaultService(Path(self.config.get("vault_directory")))
        except StorageError as e:
            self.vault = None
            QMessageBox.warning(self, "Vault unavailable",
                                f"{e}\n\nYou can pick a different location in Settings.")
        self._update_topbar()
        self.view_page.refresh()
        self.settings_page.refresh()

    def change_directory(self, parent: Path):
        vault = create_vault(parent)              # raises StorageError (user-safe message)
        self.config.update(default_directory=str(parent), vault_directory=str(vault))
        self.load_vault()

    def _update_topbar(self):
        self.user_label.setText(self.config.get("username"))
        self.path_label.setText(self.config.get("vault_directory"))

    def _navigate(self, index: int):
        self.stack.setCurrentIndex(index)
        if index == 0:
            self.view_page.refresh()

    def closeEvent(self, e):
        self._settings.setValue("geometry", self.saveGeometry())
        super().closeEvent(e)
