import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox

from config.config_manager import ConfigError, ConfigManager
from ui.main_window import MainWindow
from ui.setup_dialog import SetupDialog
from ui.styles import STYLESHEET


def selftest(out_path: str, vault_dir: str | None = None) -> int:
    """Headless check for packaged builds: load the model, predict, write JSON to out_path.
    With vault_dir, also decrypts every file of that existing vault in memory (counts only; no
    contents are written) to prove old data is still readable after an upgrade."""
    import json
    result = {"ok": False}
    try:
        from paths import model_path
        from services.ml_model_service import get_model_service
        svc = get_model_service()
        pred = svc.predict(svc.default_parameters())
        result.update(ok=True, model_path=str(model_path()), classes=svc.classes,
                      sample_prediction=pred.label, confidence=round(pred.confidence, 4))
        # Encrypt/decrypt round trip in memory for every level (no files, no key file touched).
        import tempfile
        from services.encryption_service import LEVEL_ALGORITHM, EncryptionService
        enc, data, trips = EncryptionService(), b"DEDV selftest " * 100, {}
        with tempfile.TemporaryDirectory() as tmp:
            for level in LEVEL_ALGORITHM:
                dest = Path(tmp) / f"{level}.enc"
                r = enc.encrypt_data(data, dest, level)
                trips[level] = (r.algorithm, enc.decrypt_bytes(dest, r.algorithm, r.params, r.secrets) == data)
        result["round_trips"] = trips
        from PySide6.QtPdf import QPdfDocument      # PDF viewer support is bundled
        from PySide6.QtPdfWidgets import QPdfView   # noqa: F401
        result["qtpdf"] = QPdfDocument.__name__
        result["ok"] = all(v[1] for v in trips.values())
        if vault_dir:
            from services.vault_service import VaultService
            vault = VaultService(Path(vault_dir))
            files = vault.list_files()
            readable = 0
            for m in files:
                try:
                    vault.read_file(m.file_id)
                    readable += 1
                except Exception as e:
                    result.setdefault("unreadable", []).append(f"{m.original_name}: {e}")
            result["vault"] = {"files": len(files), "readable": readable}
            result["ok"] = result["ok"] and readable == len(files)
    except Exception as e:      # reported in the file; exit code tells the caller
        result["error"] = f"{type(e).__name__}: {e}"
    Path(out_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0 if result["ok"] else 1


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "--selftest":
        return selftest(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
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
