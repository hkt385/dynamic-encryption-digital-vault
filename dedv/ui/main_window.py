from pathlib import Path

from PySide6.QtCore import QEvent, QPoint, QPropertyAnimation, QSettings, Qt, QTimer, QVariantAnimation
from PySide6.QtWidgets import (QApplication, QButtonGroup, QDialog, QFrame, QHBoxLayout, QLabel,
                               QMainWindow, QStackedWidget, QVBoxLayout, QWidget)

from config.config_manager import ConfigManager
from services.security_decision_service import SecurityDecisionEngine
from services.storage_service import StorageError, create_vault
from services.vault_service import VaultService
from services.viewer_service import STALE_AFTER_SECONDS, SWEEP_EVERY_SECONDS, TempFiles
from ui.developer_page import DeveloperPage
from ui.edit_page import EditPage
from ui.loading_overlay import LoadingOverlay, TaskRunner
from ui.settings_page import SettingsPage
from ui.unlock_dialog import UnlockDialog, open_vault
from ui.upload_page import UploadPage
from ui.view_page import ViewPage
from ui import styles
from ui.widgets import GLYPHS, NavButton, enter
from ui import backdrop

DEFAULT_AUTO_LOCK_MINUTES = 10
PANE_WIDTH, COMPACT_WIDTH = 248, 56            # expanded side bar / icon rail
_ACTIVITY = (QEvent.KeyPress, QEvent.MouseButtonPress, QEvent.MouseMove, QEvent.Wheel)


class _NavPane(QFrame):
    """Side bar; reports size changes so the selection pill can follow its entry."""

    def __init__(self, on_resize):
        super().__init__()
        self._on_resize = on_resize

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._on_resize()


class MainWindow(QMainWindow):
    def __init__(self, config: ConfigManager, vault: VaultService | None = None):
        """`vault` is an open, unlocked vault (ui.unlock_dialog.open_vault), or None if the
        configured vault could not be opened; Settings can then pick another location."""
        super().__init__()
        backdrop.prepare(self)                 # Mica (main window) / Acrylic (dialog)
        self.config = config
        self.vault = vault
        self.setWindowTitle("Dynamic Encryption Digital Vault")
        self.setMinimumSize(1200, 700)

        self._settings = QSettings("DEDV", "DEDV")
        geo = self._settings.value("geometry")
        if geo:
            self.restoreGeometry(geo)

        # Side bar on Mica: menu button, account card, pages, and Lock / Settings / Developer at the
        # bottom. It collapses to an icon rail; the accent pill slides to the selected page.
        self.sidebar = sidebar = _NavPane(lambda: self._place_pill())
        sidebar.setObjectName("navPane")
        sidebar.setFixedWidth(PANE_WIDTH)
        sl = QVBoxLayout(sidebar)
        sl.setContentsMargins(8, 8, 8, 12)
        sl.setSpacing(4)
        self.menu_btn = NavButton("", GLYPHS["menu"], checkable=False)
        self.menu_btn.clicked.connect(lambda: self.set_compact(not self.compact, animate=True))
        sl.addWidget(self.menu_btn)
        sl.addSpacing(4)
        self.avatar = QLabel()
        self.avatar.setObjectName("avatar")
        self.avatar.setFixedSize(36, 36)
        self.avatar.setAlignment(Qt.AlignCenter)
        self.user_label = QLabel()
        self.user_label.setObjectName("accountName")
        self.path_label = QLabel()
        self.path_label.setObjectName("accountPath")
        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(self.user_label)
        names.addWidget(self.path_label)
        account = QHBoxLayout()
        account.setContentsMargins(2, 0, 2, 16)        # avatar centred on the icons in both widths
        account.setSpacing(12)
        account.addWidget(self.avatar)
        account.addLayout(names, 1)
        sl.addLayout(account)

        # Prediction engine (model loaded once) and the shared "Encrypting" overlay/runner.
        self.engine = SecurityDecisionEngine()
        self.overlay = LoadingOverlay(self)
        self.runner = TaskRunner(self.overlay)
        self.temp_files = TempFiles()
        self.temp_files.sweep_stale()          # plaintext copies left by an earlier run
        self._sweep = QTimer(self)             # and copies opened externally more than 5 min ago
        self._sweep.timeout.connect(lambda: self.temp_files.sweep_stale(STALE_AFTER_SECONDS))
        self._sweep.start(SWEEP_EVERY_SECONDS * 1000)

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

        self.lock_btn = NavButton("Lock vault", GLYPHS["lock"], checkable=False)
        self.lock_btn.setToolTip("Lock the vault now. The password is needed to open it again.")
        self.lock_btn.clicked.connect(self.lock_vault)
        self.nav = group = QButtonGroup(self)
        group.setExclusive(True)
        for i, (label, glyph, page) in enumerate((("View", "view", self.view_page),
                                                  ("Upload", "upload", self.upload_page),
                                                  ("Edit", "edit", self.edit_page),
                                                  ("Settings", "settings", self.settings_page),
                                                  ("Developer", "developer", self.developer_page))):
            self.stack.addWidget(page)
            b = NavButton(label, GLYPHS[glyph])
            group.addButton(b, i)
            if i == 3:                         # Settings and Developer sit at the bottom, under Lock
                sl.addStretch()
                sl.addWidget(self.lock_btn)
            sl.addWidget(b)
            if i == 0:
                b.setChecked(True)
        group.idClicked.connect(self._navigate)
        self.pill = QWidget(sidebar)
        self.pill.setObjectName("navPill")
        self.pill.setAttribute(Qt.WA_StyledBackground, True)
        self.pill.resize(3, 16)
        self._pill_anim = QPropertyAnimation(self.pill, b"pos", self)
        self._pill_anim.setEasingCurve(styles.ease())
        self._rail_anim = QVariantAnimation(self)
        self._rail_anim.setEasingCurve(styles.ease())
        self._rail_anim.valueChanged.connect(lambda w: sidebar.setFixedWidth(int(w)))
        self._rail_anim.finished.connect(self._rail_settled)
        self.compact = False
        self.set_compact(self._settings.value("navCompact", False, type=bool), animate=False)

        content = QWidget()                    # the pages sit on a layer with a rounded corner
        content.setObjectName("content")
        content.setAttribute(Qt.WA_StyledBackground, True)
        rl = QVBoxLayout(content)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(self.stack)

        central = QWidget()
        central.setObjectName("root")
        cl = QHBoxLayout(central)
        cl.setContentsMargins(0, 8, 0, 0)
        cl.setSpacing(0)
        cl.addWidget(sidebar)
        cl.addWidget(content, 1)
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

    # ---- side bar --------------------------------------------------------------------------------
    def set_compact(self, compact: bool, animate: bool = True):
        """Collapse the side bar to an icon rail (labels become tooltips) or expand it again."""
        self.compact = compact
        self.menu_btn.setToolTip("Expand navigation" if compact else "Collapse navigation")
        for b in self.nav.buttons():
            b.setToolTip(b.text() if compact else "")
        if compact:                         # account text goes first, and comes back once expanded
            self.user_label.hide()
            self.path_label.hide()
        target = COMPACT_WIDTH if compact else PANE_WIDTH
        ms = styles.motion(styles.NORMAL) if animate else 0
        self._rail_anim.stop()
        if ms:
            self._rail_anim.setDuration(ms)
            self._rail_anim.setStartValue(self.sidebar.width())
            self._rail_anim.setEndValue(target)
            self._rail_anim.start()
        else:
            self.sidebar.setFixedWidth(target)
            self._rail_settled()

    def _rail_settled(self):
        if not self.compact:
            self.user_label.show()
            self.path_label.show()
        self._place_pill()

    def _place_pill(self, animate: bool = False):
        """Accent pill beside the selected page; slides there when the page changes."""
        btn = self.nav.checkedButton() if hasattr(self, "pill") else None
        if btn is None:
            return
        target = QPoint(btn.x(), btn.y() + (btn.height() - self.pill.height()) // 2)
        self.pill.raise_()
        self._pill_anim.stop()
        ms = styles.motion(styles.NORMAL) if animate and self.isVisible() else 0
        if ms:
            self._pill_anim.setDuration(ms)
            self._pill_anim.setStartValue(self.pill.pos())
            self._pill_anim.setEndValue(target)
            self._pill_anim.start()
        else:
            self.pill.move(target)

    def _update_topbar(self):
        name, path = self.config.get("username") or "", self.config.get("vault_directory") or ""
        self.avatar.setText(name[:1].upper() or "?")
        self.user_label.setText(name)
        width = PANE_WIDTH - 16 - 4 - 36 - 12          # pane minus margins, avatar and gap
        self.path_label.setText(self.path_label.fontMetrics().elidedText(path, Qt.ElideMiddle, width))
        self.path_label.setToolTip(path)
        self.lock_btn.setEnabled(self.vault is not None)

    def _navigate(self, index: int):
        self.nav.button(index).setChecked(True)
        self.stack.setCurrentIndex(index)
        if index == 0:
            self.view_page.refresh()
        elif index == 2:
            self.edit_page.refresh()
        elif index == 4:
            self.developer_page.refresh()
        self._place_pill(animate=True)
        enter(self.stack.currentWidget())

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
        self._settings.setValue("navCompact", self.compact)
        super().closeEvent(e)
