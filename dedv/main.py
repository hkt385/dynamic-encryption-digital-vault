import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from config.config_manager import ConfigError, ConfigManager
from ui.main_window import MainWindow
from ui.setup_dialog import SetupDialog
from ui.styles import STYLESHEET


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)

    config = ConfigManager()
    if not config.load():
        if config.was_corrupt:
            QMessageBox.information(None, "DEDV", "Your settings file could not be read. "
                                    "Please set up the vault again.")
        dlg = SetupDialog()
        if dlg.exec() != SetupDialog.Accepted or not dlg.result:
            return 0
        try:
            config.update(**dlg.result)
        except ConfigError as e:
            QMessageBox.critical(None, "DEDV", str(e))
            return 1

    window = MainWindow(config)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
