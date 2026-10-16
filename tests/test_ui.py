import pytest

from config.config_manager import ConfigManager
from services.security_decision_service import CHOICE_REQUIRED, SecurityDecisionEngine
from ui.high_critical_dialog import HighCriticalDialog
from ui.parameter_bar import ParameterBar
from ui.upload_page import Entry, UploadPage


def _bar(qapp, model, path):
    cfg = ConfigManager(path)
    cfg.load()
    return cfg, ParameterBar(cfg, model)


def test_first_launch_defaults_then_persist_across_restart(qapp, model, tmp_path):
    path = tmp_path / "settings.json"
    cfg, bar = _bar(qapp, model, path)
    assert bar.values() == model.default_parameters()          # valid defaults on first launch
    bar.combos["Sensitivity"].setCurrentText("Very High")
    bar._on_user_change()
    bar.combos["Multiple Devices"].setCurrentText("Yes, regularly")
    bar._on_user_change()
    # "restart": a brand-new config and widgets read from the file
    cfg2, bar2 = _bar(qapp, model, path)
    assert bar2.values()["Sensitivity"] == "Very High"
    assert bar2.values()["Multiple Devices"] == "Yes, regularly"
    assert "key" not in path.read_text().lower()


def test_unsupported_saved_values_fall_back_to_defaults(qapp, model, tmp_path):
    path = tmp_path / "settings.json"
    ConfigManager(path).update(model_parameters={"Sensitivity": "Removed Option",
                                                 "Access Frequency": "Daily", "Bogus": 1})
    cfg, bar = _bar(qapp, model, path)
    assert bar.values()["Sensitivity"] == model.default_parameters()["Sensitivity"]
    assert bar.values()["Access Frequency"] == "Daily"
    assert set(cfg.get_model_parameters()) == set(bar.values())   # file repaired


class _Runner:
    """Stand-in runner for tests that only exercise prediction/dialog logic."""
    busy = False

    def run(self, fn, on_done, on_error):
        on_done(fn())
        return True


def _page(model, params, account, tmp_path):
    engine = SecurityDecisionEngine(model)
    cfg = ConfigManager(tmp_path / "s.json")
    cfg.update(account_type=account, model_parameters=params)
    page = UploadPage(lambda: None, cfg, engine, _Runner())
    f = tmp_path / "a.txt"
    f.write_text("data")
    page.entries = [Entry(f)]
    return page, f


def _stub_dialog(monkeypatch, choice):
    calls = []

    def fake_exec(self):
        calls.append(self.windowTitle())
        self.choice = choice
        return HighCriticalDialog.Accepted if choice else HighCriticalDialog.Rejected
    monkeypatch.setattr(HighCriticalDialog, "exec", fake_exec)
    return calls


def test_enterprise_popup_once_and_choice_applies(qapp, model, params_by_class, tmp_path, monkeypatch):
    calls = _stub_dialog(monkeypatch, "Critical")
    page, f = _page(model, params_by_class["High/Critical"], "Enterprise", tmp_path)
    page.run_prediction()
    page._render()
    page._render()
    page._prompt_pending()                                       # rerenders must not re-prompt
    assert len(calls) == 1
    d = page.entries[0].decision
    assert d.level == "Critical" and d.predicted == "High/Critical"
    assert page.table.item(0, 4).text() == "Critical"
    assert f.read_text() == "data"


def test_choice_is_attached_to_the_right_file(qapp, model, params_by_class, tmp_path, monkeypatch):
    answers = iter(["High", "Critical"])

    def fake_exec(self):
        self.choice = next(answers)
        return HighCriticalDialog.Accepted
    monkeypatch.setattr(HighCriticalDialog, "exec", fake_exec)
    page, _ = _page(model, params_by_class["High/Critical"], "Enterprise", tmp_path)
    second = tmp_path / "b.txt"
    second.write_text("b")
    page.entries.append(Entry(second))
    page.run_prediction()
    assert [(e.path.name, e.decision.level) for e in page.entries] == [("a.txt", "High"), ("b.txt", "Critical")]


def test_dismissal_assigns_nothing_and_can_reopen(qapp, model, params_by_class, tmp_path, monkeypatch):
    _stub_dialog(monkeypatch, None)
    page, _ = _page(model, params_by_class["High/Critical"], "Enterprise", tmp_path)
    page.run_prediction()
    d = page.entries[0].decision
    assert d.status == CHOICE_REQUIRED and d.level is None
    assert page.table.item(0, 4).text() == "Choice required"
    assert not page.store_btn.isEnabled()
    assert page.table.cellWidget(0, 5) is not None
    _stub_dialog(monkeypatch, "High")
    page._reopen(page.entries[0])
    assert d.level == "High"


@pytest.mark.parametrize("label", ["Low", "Standard", "Enhanced"])
def test_no_popup_for_lower_levels(qapp, model, params_by_class, tmp_path, monkeypatch, label):
    calls = _stub_dialog(monkeypatch, "High")
    page, _ = _page(model, params_by_class[label], "Enterprise", tmp_path)
    page.run_prediction()
    assert calls == [] and page.entries[0].decision.level == label


def test_personal_never_shows_popup_or_high_critical(qapp, model, params_by_class, tmp_path, monkeypatch):
    calls = _stub_dialog(monkeypatch, "High")
    page, _ = _page(model, params_by_class["High/Critical"], "Personal", tmp_path)
    page.run_prediction()
    assert calls == []
    assert page.entries[0].decision.level is None
    assert page.table.item(0, 4).text() == "Not available"
    assert not page.store_btn.isEnabled()


def test_invalidate_clears_predictions(qapp, model, params_by_class, tmp_path, monkeypatch):
    _stub_dialog(monkeypatch, "High")
    page, _ = _page(model, params_by_class["Low"], "Personal", tmp_path)
    page.run_prediction()
    page.invalidate()
    assert page.entries[0].decision is None
