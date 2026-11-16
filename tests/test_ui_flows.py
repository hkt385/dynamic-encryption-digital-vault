import hashlib
import threading
import time

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMainWindow, QMessageBox, QWidget

from config.config_manager import ConfigManager
from conftest import wait_until
from services.security_decision_service import FINAL, SecurityDecision
from ui.edit_page import EditPage, levels_for
from ui.file_viewer import FileViewerDialog
from ui.loading_overlay import OVERLAY_TEXT, LoadingOverlay, TaskRunner
from ui.main_window import MainWindow
from ui.parameter_bar import ParameterBar
from ui.upload_page import Entry, UploadPage
from ui.view_page import ViewPage
from services.vault_service import VaultService

CONTENT = b"top secret\n" * 100


@pytest.fixture
def host(qapp):
    win = QMainWindow()
    win.setCentralWidget(QWidget())
    win.resize(900, 600)
    win.show()
    overlay = LoadingOverlay(win)
    return win, overlay, TaskRunner(overlay)


@pytest.fixture(autouse=True)
def no_blocking_boxes(monkeypatch):
    """Record message boxes instead of blocking on them."""
    shown = []
    for name in ("information", "warning", "critical"):
        monkeypatch.setattr(QMessageBox, name, staticmethod(lambda *a, _n=name: shown.append((_n, a[1:])) or 0))
    return shown


# ---- shared loading component -----------------------------------------------------------------
def test_overlay_visible_for_whole_operation_then_hidden(host):
    win, overlay, runner = host
    gate, results = threading.Event(), []
    ticks = []
    t = QTimer()
    t.timeout.connect(lambda: ticks.append(1))
    t.start(10)
    assert runner.run(lambda: (gate.wait(5), "ok")[1], results.append, results.append)
    assert overlay.isVisible() and overlay.label.text() == "Encrypting" == OVERLAY_TEXT
    assert overlay.spinner.running                               # spinner rotating
    assert not win.centralWidget().isEnabled()                   # page underneath is blocked
    n = len(ticks)
    wait_until(lambda: len(ticks) > n + 5, 3)
    assert len(ticks) > n + 5 and overlay.isVisible()            # GUI stays responsive meanwhile
    gate.set()
    assert wait_until(lambda: bool(results))
    assert results == ["ok"]
    assert not overlay.isVisible() and not overlay.spinner.running
    assert win.centralWidget().isEnabled() and not runner.busy


def test_overlay_has_no_progress_indicators(host):
    from PySide6.QtWidgets import QLabel, QProgressBar
    _, overlay, _ = host
    assert not overlay.findChildren(QProgressBar)
    assert [l.text() for l in overlay.findChildren(QLabel)] == ["Encrypting"]


def test_duplicate_requests_refused_while_busy(host):
    _, overlay, runner = host
    gate, calls = threading.Event(), []
    assert runner.run(lambda: calls.append(1) or gate.wait(5), lambda r: None, lambda m: None)
    assert not runner.run(lambda: calls.append(2), lambda r: None, lambda m: None)
    gate.set()
    assert wait_until(lambda: not runner.busy)
    assert calls == [1]


def test_overlay_reset_after_exception_and_after_callback_error(host):
    _, overlay, runner = host
    errors = []
    runner.run(lambda: 1 / 0, lambda r: None, errors.append)
    assert wait_until(lambda: bool(errors))
    assert "ZeroDivisionError" in errors[0] and not overlay.isVisible() and not runner.busy

    errors.clear()

    def bad_callback(_):
        raise RuntimeError("callback bug")
    runner.run(lambda: 1, bad_callback, errors.append)
    assert wait_until(lambda: bool(errors))
    assert not overlay.isVisible() and not runner.busy
    assert runner.run(lambda: 2, lambda r: errors.append("again"), errors.append)     # usable again
    assert wait_until(lambda: errors[-1] == "again")


# ---- upload page --------------------------------------------------------------------------------
def _upload_setup(qapp, model, tmp_path, host, level, params, account="Enterprise"):
    from services.security_decision_service import SecurityDecisionEngine
    win, overlay, runner = host
    cfg = ConfigManager(tmp_path / "s.json")
    cfg.update(account_type=account, model_parameters=params)
    vault = VaultService(tmp_path / "DEDV")
    page = UploadPage(lambda: vault, cfg, SecurityDecisionEngine(model), runner)
    src = tmp_path / "doc.txt"
    src.write_bytes(CONTENT)
    page.entries = [Entry(src)]
    return page, vault, src, overlay, runner


def test_encrypt_button_shows_overlay_and_reports_success_only_after_completion(
        qapp, model, params_by_class, tmp_path, host, no_blocking_boxes):
    page, vault, src, overlay, runner = _upload_setup(qapp, model, tmp_path, host, "Low", params_by_class["Low"])
    page.run_prediction()
    assert page.store_btn.isEnabled()
    gate = threading.Event()
    real = vault.store_files

    def slow(items, account):
        gate.wait(10)
        return real(items, account)
    vault.store_files = slow
    page.store_btn.click()
    assert overlay.isVisible() and overlay.label.text() == "Encrypting"
    assert not page.store_btn.isEnabled()                         # disabled while running
    page.store()                                                   # repeated click: ignored
    assert vault.list_files() == [] and not no_blocking_boxes     # nothing reported yet
    gate.set()
    assert wait_until(lambda: bool(no_blocking_boxes))
    assert not overlay.isVisible()
    kind, args = no_blocking_boxes[-1]
    assert kind == "information" and "1 file(s) encrypted" in args[1]
    files = vault.list_files()
    assert len(files) == 1 and files[0].security_level == "Low" and files[0].algorithm == "AES-128-GCM"
    assert page.entries == [] and src.read_bytes() == CONTENT


def test_encrypt_failure_hides_overlay_and_reports_error(qapp, model, params_by_class, tmp_path, host,
                                                          no_blocking_boxes):
    page, vault, src, overlay, runner = _upload_setup(qapp, model, tmp_path, host, "Low", params_by_class["Low"])
    page.run_prediction()
    vault.store_files = lambda *a: (_ for _ in ()).throw(RuntimeError("kaboom"))
    page.store_btn.click()
    assert wait_until(lambda: bool(no_blocking_boxes))
    assert not overlay.isVisible() and no_blocking_boxes[-1][0] == "critical"
    assert "kaboom" in no_blocking_boxes[-1][1][1]
    assert page.store_btn.isEnabled() and vault.list_files() == []


def test_final_selected_level_is_the_level_used_for_encryption(qapp, model, params_by_class, tmp_path, host,
                                                                no_blocking_boxes, monkeypatch):
    from ui.high_critical_dialog import HighCriticalDialog
    chosen = iter(["Critical"])

    def fake_exec(self):
        self.choice = next(chosen)
        return HighCriticalDialog.Accepted
    monkeypatch.setattr(HighCriticalDialog, "exec", fake_exec)
    page, vault, src, overlay, runner = _upload_setup(qapp, model, tmp_path, host, "x", params_by_class["High/Critical"])
    page.run_prediction()
    page.store_btn.click()
    assert wait_until(lambda: bool(no_blocking_boxes))
    meta = vault.list_files()[0]
    assert (meta.security_level, meta.predicted_level, meta.algorithm) == (
        "Critical", "High/Critical", "AES-256-GCM+ML-KEM-1024")
    assert vault.read_file(meta.file_id)[1] == CONTENT


def test_personal_cannot_encrypt_high_critical(qapp, model, params_by_class, tmp_path, host):
    page, vault, *_ = _upload_setup(qapp, model, tmp_path, host, "x", params_by_class["High/Critical"], "Personal")
    page.run_prediction()
    assert not page.store_btn.isEnabled()
    page.store()
    assert wait_until(lambda: not page.runner.busy)
    assert vault.list_files() == []


# ---- parameters only on the Upload page -------------------------------------------------------------
def test_dropdowns_exist_only_on_upload_page_and_persist(qapp, tmp_path, model):
    cfg = ConfigManager(tmp_path / "settings.json")
    cfg.update(username="u", account_type="Enterprise", default_directory=str(tmp_path),
               vault_directory=str(tmp_path / "DEDV"))
    win = MainWindow(cfg)
    bars = win.findChildren(ParameterBar)
    assert len(bars) == 1 and win.upload_page.isAncestorOf(bars[0])
    for page in (win.view_page, win.edit_page, win.settings_page, win.developer_page):
        assert not page.findChildren(ParameterBar)
    from PySide6.QtWidgets import QComboBox
    # upload page: bar is above the file controls
    assert bars[0].y() < win.upload_page.select_btn.y() or not win.isVisible()
    bar = win.upload_page.param_bar
    bar.combos["Sensitivity"].setCurrentText("Very High")
    bar._on_user_change()
    win._navigate(2)
    win._navigate(1)                                            # navigating does not reset
    assert bar.values()["Sensitivity"] == "Very High"
    cfg2 = ConfigManager(tmp_path / "settings.json")
    assert cfg2.load()
    win2 = MainWindow(cfg2)
    assert win2.upload_page.param_bar.values()["Sensitivity"] == "Very High"
    assert [win.stack.widget(i) for i in range(win.stack.count())] == [
        win.view_page, win.upload_page, win.edit_page, win.settings_page, win.developer_page]


# ---- view page: double-click open ----------------------------------------------------------------------
def _stored_vault(tmp_path, name, content, level="Standard"):
    vault = VaultService(tmp_path / "DEDV")
    src = tmp_path / name
    src.write_bytes(content)
    d = SecurityDecision(FINAL, "Enterprise", predicted=level, level=level)
    assert vault.store_files([(src, d)], "Enterprise").stored == [name]
    return vault, vault.list_files()[-1]


def test_double_click_opens_in_memory_without_touching_encrypted_file(qapp, tmp_path, monkeypatch):
    vault, meta = _stored_vault(tmp_path, "note.txt", CONTENT)
    enc = vault.encrypted_dir / meta.encrypted_name
    before = hashlib.sha256(enc.read_bytes()).hexdigest()
    opened = []
    monkeypatch.setattr(FileViewerDialog, "exec", lambda self: opened.append(self.body.toPlainText()) or 0)
    page = ViewPage(lambda: vault)
    page.refresh()
    assert page.table.item(0, 5).text() == "AES-256" and page.table.item(0, 6).text() == "Standard"
    page._on_double_click(0, 0)
    assert opened and opened[0].startswith("top secret")
    assert hashlib.sha256(enc.read_bytes()).hexdigest() == before
    assert not list((tmp_path / "tmpview").glob("*")) if (tmp_path / "tmpview").exists() else True   # no plaintext on disk


def test_unreadable_file_shows_clear_error(qapp, tmp_path, no_blocking_boxes):
    vault, meta = _stored_vault(tmp_path, "note.txt", CONTENT)
    (vault.encrypted_dir / meta.encrypted_name).write_bytes(b"junk" * 20)
    page = ViewPage(lambda: vault)
    page.refresh()
    page._on_double_click(0, 0)
    assert no_blocking_boxes[-1][0] == "warning" and "corrupted" in no_blocking_boxes[-1][1][1]


def test_executables_are_never_launched(qapp, tmp_path, no_blocking_boxes, monkeypatch):
    vault, meta = _stored_vault(tmp_path, "setup.exe", b"MZ" + b"\0" * 50)
    launched = []
    from PySide6.QtGui import QDesktopServices
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda u: launched.append(u) or True)
    page = ViewPage(lambda: vault)
    page.refresh()
    page._on_double_click(0, 0)
    assert not launched and "does not launch" in no_blocking_boxes[-1][1][1]
    assert not (tmp_path / "tmpview").exists() or not list((tmp_path / "tmpview").iterdir())


def test_unknown_type_needs_confirmation_and_temp_copy_is_cleaned(qapp, tmp_path, monkeypatch):
    vault, meta = _stored_vault(tmp_path, "data.xyz", b"payload")
    from PySide6.QtGui import QDesktopServices
    launched = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda u: launched.append(u.toLocalFile()) or True)
    page = ViewPage(lambda: vault)
    page.refresh()
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.No))
    page._on_double_click(0, 0)
    assert not launched and not list((tmp_path / "tmpview").glob("*"))         # declined: nothing written
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.Yes))
    page._on_double_click(0, 0)
    from pathlib import Path
    assert len(launched) == 1 and Path(launched[0]).read_bytes() == b"payload"
    assert tmp_path not in Path(launched[0]).parents or Path(launched[0]).parents[1].name == "tmpview"
    assert vault.vault_dir not in Path(launched[0]).parents                    # outside the vault
    assert page.temp_files.cleanup() == [] and not Path(launched[0]).exists()


def test_viewer_handles_text_image_pdf_and_corruption(qapp):
    from PySide6.QtCore import QBuffer, QIODevice
    from PySide6.QtGui import QImage, QPainter, QPdfWriter
    img = QImage(20, 20, QImage.Format_RGB32)
    img.fill(0xFF0000)
    b = QBuffer()
    b.open(QIODevice.WriteOnly)
    img.save(b, "PNG")
    png = bytes(b.data())
    assert not FileViewerDialog("a.png", "image", png).error
    assert FileViewerDialog("a.png", "image", png[:30] + b"zzzz").error
    pdf_buf = QBuffer()
    pdf_buf.open(QIODevice.WriteOnly)
    w = QPdfWriter(pdf_buf)
    p = QPainter(w)
    p.drawText(100, 100, "hello")
    p.end()
    pdf = bytes(pdf_buf.data())
    assert not FileViewerDialog("a.pdf", "pdf", pdf).error
    assert FileViewerDialog("a.pdf", "pdf", b"%PDF-1.4 broken").error
    assert not FileViewerDialog("a.txt", "text", b"hi").error


# ---- edit page ------------------------------------------------------------------------------------------
def _edit_setup(tmp_path, host, account, level="Standard"):
    win, overlay, runner = host
    vault, meta = _stored_vault(tmp_path, "note.txt", CONTENT, level)
    page = EditPage(lambda: vault, lambda: account, runner)
    page.refresh()
    return page, vault, meta, overlay


def test_edit_page_shows_current_details_and_account_valid_targets(qapp, tmp_path, host):
    page, vault, meta, _ = _edit_setup(tmp_path, host, "Personal")
    assert page.details["Current security level"].text() == "Standard"
    assert page.details["Current algorithm"].text() == "AES-256"
    targets = [page.target.itemData(i) for i in range(page.target.count())]
    assert targets == ["Low", "Enhanced"]                      # no High/Critical for Personal, not current
    assert levels_for("Enterprise") == ("Low", "Standard", "Enhanced", "High", "Critical")
    assert "High" not in levels_for("Personal") and "Critical" not in levels_for("Personal")


def test_reencrypt_button_uses_same_overlay_and_updates_everything(qapp, tmp_path, host, no_blocking_boxes):
    page, vault, meta, overlay = _edit_setup(tmp_path, host, "Enterprise")
    page.target.setCurrentIndex(page.target.findData("High"))
    gate = threading.Event()
    real = vault.reencrypt
    vault.reencrypt = lambda *a: (gate.wait(10), real(*a))[1]
    page.button.click()
    assert overlay.isVisible() and overlay.label.text() == "Encrypting"
    assert not page.button.isEnabled()
    page.reencrypt()                                            # duplicate click ignored
    gate.set()
    assert wait_until(lambda: bool(no_blocking_boxes))
    assert not overlay.isVisible()
    assert no_blocking_boxes[-1][0] == "information" and "ChaCha20-Poly1305" in no_blocking_boxes[-1][1][1]
    assert page.details["Current security level"].text() == "High"
    assert page.details["Current algorithm"].text() == "ChaCha20-Poly1305"
    assert vault.list_files()[0].algorithm == "CHACHA20-POLY1305"
    assert vault.read_file(meta.file_id)[1] == CONTENT


def test_failed_reencrypt_hides_overlay_and_preserves_file(qapp, tmp_path, host, no_blocking_boxes, monkeypatch):
    page, vault, meta, overlay = _edit_setup(tmp_path, host, "Enterprise")
    from services import encryption_service as es
    monkeypatch.setattr(es.chacha, "encrypt_bytes", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    page.target.setCurrentIndex(page.target.findData("High"))
    page.button.click()
    assert wait_until(lambda: bool(no_blocking_boxes))
    assert not overlay.isVisible() and no_blocking_boxes[-1][0] == "warning"
    assert page.button.isEnabled()
    assert vault.list_files()[0] == meta and vault.read_file(meta.file_id)[1] == CONTENT
