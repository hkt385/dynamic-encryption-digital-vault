from pathlib import Path

from PySide6.QtCore import QEvent, QSettings, QTimer
from PySide6.QtWidgets import (QApplication, QButtonGroup, QDialog, QFrame, QHBoxLayout, QLabel,
                               QMainWindow, QPushButton, QStackedWidget, QVBoxLayout, QWidget)

from config.config_manager import ConfigManager
from services.security_decision_service import SecurityDecisionEngine
from services.storage_service import StorageError, create_vault
from services.vault_service import VaultService
from services.viewer_service import TempFiles
from ui.developer_page import DeveloperPage
from ui.edit_page import EditPage
from ui.loading_overlay import LoadingOverlay, TaskRunner
from ui.settings_page import SettingsPage
from ui.unlock_dialog import UnlockDialog, open_vault
from ui.upload_page import UploadPage
from ui.view_page import ViewPage

DEFAULT_AUTO_LOCK_MINUTES = 10
_ACTIVITY = (QEvent.KeyPress, QEvent.MouseButtonPress, QEvent.MouseMove, QEvent.Wheel)


class MainWindow(QMainWindow):
    def __init__(self, config: ConfigManager, vault: VaultService | None = None):
        """`vault` is an open, unlocked vault (ui.unlock_dialog.open_vault), or None if the
        configured vault could not be opened; Settings can then pick another location."""
        super().__init__()
        self.config = config
        self.vault = vault
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

        # Prediction engine (model loaded once) and the shared "Encrypting" overlay/runner.
        self.engine = SecurityDecisionEngine()
        self.overlay = LoadingOverlay(self)
        self.runner = TaskRunner(self.overlay)
        self.temp_files = TempFiles()
        self.temp_files.sweep_stale()          # plaintext copies left by an earlier run

        # Pages
        self.view_page = ViewPage(lambda: self.vault, self.temp_files)
        self.upload_page = UploadPage(lambda: self.vault, config, self.engine, self.runner)
        self.edit_page = EditPage(lambda: self.vault, lambda: self.config.get("account_type"), self.runner)
        self.settings_page = SettingsPage(config, self.change_directory, lambda: self.vault)
        self.developer_page = DeveloperPage(lambda: self.vault)
        self.upload_page.stored.connect(self.view_page.refresh)
        self.upload_page.stored.connect(self.edit_page.refresh)
        self.edit_page.changed.connect(self.view_page.refresh)
        self.settings_page.changed.connect(self._update_topbar)
        self.settings_page.changed.connect(self.upload_page.invalidate)
        self.settings_page.changed.connect(self.edit_page.refresh)
        self.settings_page.changed.connect(self._restart_idle_timer)
        self.stack = QStackedWidget()

        group = QButtonGroup(self)
        group.setExclusive(True)
        for i, (label, page) in enumerate((("View", self.view_page), ("Upload", self.upload_page),
                                           ("Edit", self.edit_page), ("Settings", self.settings_page),
                                           ("Developer", self.developer_page))):
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
        self.lock_btn = QPushButton("Lock")
        self.lock_btn.setToolTip("Lock the vault now. The password is needed to open it again.")
        self.lock_btn.clicked.connect(self.lock_vault)
        tl.addWidget(self.user_label)
        tl.addStretch()
        tl.addWidget(self.path_label)
        tl.addWidget(self.lock_btn)

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

        # Auto-lock: any key or mouse activity anywhere in the application restarts the timer.
        self._idle = QTimer(self)
        self._idle.setSingleShot(True)
        self._idle.timeout.connect(self.lock_vault)
        QApplication.instance().installEventFilter(self)

        self._refresh_pages()
        self._restart_idle_timer()

    # ---- vault ---------------------------------------------------------------------------------
    def _refresh_pages(self):
        self._update_topbar()
        self.view_page.refresh()
        self.edit_page.refresh()
        self.settings_page.refresh()
        self.developer_page.refresh()

    def change_directory(self, parent: Path):
        """Open (or create) the vault under `parent` and switch to it. Raises StorageError
        (user-safe message); the current vault stays open if the new one is not unlocked."""
        vault_dir = create_vault(parent)
        new = open_vault(vault_dir, self)
        if new is None:
            raise StorageError("The other vault was not unlocked, so the vault directory was not changed.")
        if self.vault is not None:
            self.vault.close()                    # releases the old vault's cross-process lock
        self.vault = new
        self.config.update(default_directory=str(parent), vault_directory=str(vault_dir))
        self._refresh_pages()
        self._restart_idle_timer()

    def _update_topbar(self):
        self.user_label.setText(self.config.get("username"))
        self.path_label.setText(self.config.get("vault_directory"))
        self.lock_btn.setEnabled(self.vault is not None)

    def _navigate(self, index: int):
        self.stack.setCurrentIndex(index)
        if index == 0:
            self.view_page.refresh()
        elif index == 2:
            self.edit_page.refresh()
        elif index == 4:
            self.developer_page.refresh()

    # ---- locking -------------------------------------------------------------------------------
    def _restart_idle_timer(self):
        try:
            minutes = int(self.config.get("auto_lock_minutes", DEFAULT_AUTO_LOCK_MINUTES))
        except (TypeError, ValueError):
            minutes = DEFAULT_AUTO_LOCK_MINUTES
        if self.vault is not None and self.vault.session.is_unlocked and minutes > 0:
            self._idle.start(minutes * 60_000)
        else:
            self._idle.stop()

    def eventFilter(self, obj, event):
        if event.type() in _ACTIVITY and self._idle.isActive():
            self._idle.start()                    # restart with the same interval
        return False

    def lock_vault(self):
        """Lock button and idle timeout: forget the vault key, close everything that shows vault
        content, hide the window and ask for the password again."""
        if self.vault is None or not self.vault.session.is_unlocked:
            return
        if self.runner.busy:                      # never interrupt an encryption; lock right after it
            self._idle.start(2000)
            return
        self._idle.stop()
        for w in QApplication.topLevelWidgets():  # file previews, pickers, message boxes
            if isinstance(w, QDialog) and w.isVisible():
                w.reject()
        self.temp_files.cleanup()                 # decrypted copies handed to other programs
        self.vault.lock()
        self.hide()
        QTimer.singleShot(0, self._ask_unlock)

    def _ask_unlock(self):
        if self.vault is None:                    # the window was closed before the prompt came up
            return
        if UnlockDialog(self.vault.session, str(self.vault.vault_dir)).exec() == QDialog.Accepted:
            self.show()
            self._refresh_pages()
            self._restart_idle_timer()
        else:
            self.close()
            QApplication.instance().quit()

    def closeEvent(self, e):
        if self.runner.busy:                  # never abandon a half-finished encryption
            e.ignore()
            return
        self._idle.stop()
        self.temp_files.cleanup()
        if self.vault is not None:
            self.vault.close()
            self.vault = None
        self._settings.setValue("geometry", self.saveGeometry())
        super().closeEvent(e)
