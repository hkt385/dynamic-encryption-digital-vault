import pytest

from services.security_decision_service import (CHOICE_REQUIRED, ERROR, FINAL, UNSUPPORTED,
                                                SecurityDecisionEngine, validate_final_level)
from services.vault_service import VaultService


@pytest.fixture(scope="module")
def engine(model):
    return SecurityDecisionEngine(model)


@pytest.mark.parametrize("label", ["Low", "Standard", "Enhanced"])
@pytest.mark.parametrize("account", ["Personal", "Enterprise"])
def test_three_lower_classes_are_final_for_both_accounts(engine, params_by_class, label, account):
    d = engine.decide("x.txt", account, params_by_class[label])
    assert (d.status, d.predicted, d.level) == (FINAL, label, label)


def test_personal_high_critical_is_not_relabelled(engine, params_by_class):
    d = engine.decide("x.txt", "Personal", params_by_class["High/Critical"])
    assert d.status == UNSUPPORTED and d.predicted == "High/Critical" and d.level is None
    assert not d.is_final
    with pytest.raises(ValueError):
        d.choose_high_critical("High")          # Personal can never pick High/Critical


def test_enterprise_high_critical_requires_choice(engine, params_by_class):
    d = engine.decide("x.txt", "Enterprise", params_by_class["High/Critical"])
    assert d.status == CHOICE_REQUIRED and d.level is None and not d.is_final
    with pytest.raises(ValueError):
        d.choose_high_critical("Standard")
    d.choose_high_critical("Critical")
    assert d.is_final and d.level == "Critical" and d.predicted == "High/Critical"
    with pytest.raises(ValueError):             # cannot be re-chosen once final
        d.choose_high_critical("High")


def test_final_level_validation_per_account():
    for lv in ("Low", "Standard", "Enhanced"):
        validate_final_level("Personal", lv)
    for lv in ("High", "Critical", "High/Critical", None):
        with pytest.raises(ValueError):
            validate_final_level("Personal", lv)
    for lv in ("Low", "Standard", "Enhanced", "High", "Critical"):
        validate_final_level("Enterprise", lv)
    with pytest.raises(ValueError):
        validate_final_level("Enterprise", "High/Critical")


def test_errors_are_reported_not_raised(engine, model):
    assert engine.decide("x", "Personal", {"Sensitivity": "bogus"}).status == ERROR
    assert engine.decide("x", "Nonsense", model.default_parameters()).status == ERROR


def test_missing_model_is_reported_as_error(params_by_class):
    engine = SecurityDecisionEngine.__new__(SecurityDecisionEngine)
    engine._model, engine.load_error = None, "Prediction model not found: x"
    d = engine.decide("x", "Personal", params_by_class["Low"])
    assert d.status == ERROR and "not found" in d.message


def test_review_and_enhanced_notes(engine, params_by_class):
    d = engine.decide("x", "Enterprise", params_by_class["Enhanced"])
    assert any("REVIEW REQUIRED" in n for n in d.notes)      # max Enhanced confidence is below 0.70
    assert any("not reliably" in n for n in d.notes)


def test_vault_rejects_non_final_and_account_invalid_levels(tmp_path, engine, params_by_class):
    src = tmp_path / "doc.txt"
    src.write_text("hello")
    before = src.read_bytes()
    vault = VaultService(tmp_path / "DEDV")
    pending = engine.decide(src, "Enterprise", params_by_class["High/Critical"])
    unsupported = engine.decide(src, "Personal", params_by_class["High/Critical"])
    assert vault.store_files([(src, pending), (src, unsupported)], "Enterprise").stored == []
    pending.choose_high_critical("High")
    # A level the account may not hold is refused even though the decision itself is final.
    res = vault.store_files([(src, pending)], "Personal")
    assert res.stored == [] and res.failed
    assert vault.store_files([(src, pending)], "Enterprise").stored == ["doc.txt"]
    meta = vault.list_files()[0]
    assert (meta.security_level, meta.predicted_level) == ("High", "High/Critical")
    assert src.read_bytes() == before            # source file untouched
