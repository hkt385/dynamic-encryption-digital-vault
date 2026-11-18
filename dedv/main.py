import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox

from config.config_manager import ConfigError, ConfigManager
from services.storage_service import StorageError
from ui.main_window import MainWindow
from ui.setup_dialog import SetupDialog
from ui import styles
from ui.unlock_dialog import open_vault


def _selftest_vault(password: str) -> dict:
    """Full flow in a temporary vault: create password -> lock -> resume the Windows sign-in
    session -> end it (resume refused) -> unlock -> store one file per level -> read back ->
    re-encrypt -> lock -> release_key refuses -> audit chain verifies."""
    import os
    import tempfile
    from services.key_management_service import KeyStoreError
    from services.security_decision_service import (ENTERPRISE, ENTERPRISE_FINAL_LEVELS, FINAL,
                                                    HIGH_CRITICAL, SecurityDecision)
    from services.storage_service import create_vault
    from services.vault_service import VaultService
    checks, data = {}, b"DEDV selftest " * 100
    previous_sessions = os.environ.get("DEDV_SESSION_DIR")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        os.environ["DEDV_SESSION_DIR"] = str(Path(tmp) / "sessions")   # never the user's own cache
        vault = VaultService(create_vault(Path(tmp)))
        try:
            vault.session.initialize(password)
            vault.lock()
            resumed = vault.session.resume()
            vault.lock(end_session=True)
            checks["session"] = resumed and not vault.session.resume()
            vault.session.unlock(password)
            checks["unlock"] = vault.session.is_unlocked
            items = []
            for level in ENTERPRISE_FINAL_LEVELS:
                src = Path(tmp) / f"{level}.bin"
                src.write_bytes(data)
                predicted = HIGH_CRITICAL if level in ("High", "Critical") else level
                items.append((src, SecurityDecision(FINAL, ENTERPRISE, predicted=predicted, level=level,
                                                    acknowledged=True)))
            stored = vault.store_files(items, ENTERPRISE)
            files = vault.list_files()
            checks["store_every_level"] = (not stored.failed and sorted(m.security_level for m in files)
                                           == sorted(ENTERPRISE_FINAL_LEVELS))
            checks["read_back"] = all(vault.read_file(m.file_id)[1] == data for m in files)
            low = next(m for m in files if m.security_level == "Low")
            new = vault.reencrypt(low.file_id, "Critical", ENTERPRISE)
            checks["reencrypt"] = (new.algorithm != low.algorithm
                                   and vault.read_file(low.file_id)[1] == data)
            vault.lock()
            try:
                vault.keys.release_key(new.token, new.file_id, vault.session, "selftest")
                checks["locked_refuses_key"] = False
            except KeyStoreError:
                checks["locked_refuses_key"] = True
            audit_ok, rows, _ = vault.audit.verify()
            checks["audit_chain"] = audit_ok
            return {"checks": checks, "algorithms": {m.security_level: m.algorithm for m in files},
                    "audit_rows": rows}
        finally:
            vault.close()            # releases the lock file so the folder can be removed
            if previous_sessions is None:
                os.environ.pop("DEDV_SESSION_DIR", None)
            else:
                os.environ["DEDV_SESSION_DIR"] = previous_sessions


def selftest(out_path: str, vault_dir: str | None = None) -> int:
    """Headless check for packaged builds; writes JSON to out_path, exit code 0 = everything passed.
    Loads the model and predicts, then runs _selftest_vault() in a temporary folder. With vault_dir,
    also decrypts every file of that existing vault in memory (counts only; no contents are written)
    to prove old data is still readable after an upgrade. The password is read from the
    DEDV_SELFTEST_PASSWORD environment variable, never from argv."""
    import json
    import os
    result = {"ok": False}
    try:
        password = os.environ.get("DEDV_SELFTEST_PASSWORD", "")
        if not password:
            raise RuntimeError("Set the DEDV_SELFTEST_PASSWORD environment variable "
                               "(at least 12 characters) before running --selftest.")
        from paths import model_path
        from services.ml_model_service import get_model_service
        svc = get_model_service()
        pred = svc.predict(svc.default_parameters())
        result.update(model_path=str(model_path()), classes=svc.classes,
                      sample_prediction=pred.label, confidence=round(pred.confidence, 4))
        from PySide6.QtPdf import QPdfDocument      # PDF viewer support is bundled
        from PySide6.QtPdfWidgets import QPdfView   # noqa: F401
        result["qtpdf"] = QPdfDocument.__name__
        result["vault_flow"] = _selftest_vault(password)
        result["ok"] = all(result["vault_flow"]["checks"].values())
        if vault_dir:
            from services.vault_service import VaultService
            vault = VaultService(Path(vault_dir))
            if vault.needs_migration:
                raise RuntimeError("This vault was written by DEDV 0.1; start the app once to upgrade it.")
            vault.session.unlock(password)
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
    styles.apply(app)

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

    try:
        vault = open_vault(Path(config.get("vault_directory")))   # unlock / first password / upgrade
    except StorageError as e:
        vault = None                         # Settings can still pick a different location
        QMessageBox.warning(None, "Vault unavailable",
                            f"{e}\n\nYou can pick a different location in Settings.")
    else:
        if vault is None:                    # the user closed the password dialog
            return 0

    window = MainWindow(config, vault)
    app.aboutToQuit.connect(window.temp_files.cleanup)   # also on logoff, not only on window close
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
