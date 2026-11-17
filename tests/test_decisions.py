import pytest

from services.security_decision_service import (CHOICE_REQUIRED, ERROR, FINAL, HIGH_CRITICAL_OPTIONS,
                                                UNSUPPORTED, SecurityDecision, SecurityDecisionEngine,
                                                floor_level, is_override, validate_final_level)
from conftest import new_vault


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


def test_floor_and_override_rules():
    assert [floor_level(p) for p in ("Low", "Enhanced", "High/Critical", "", None, "bogus")] == [
        "Low", "Enhanced", "High", None, None, None]
    assert is_override("Low", "High") and not is_override("Low", "Low")
    assert not is_override("High/Critical", "High") and not is_override("High/Critical", "Critical")
    assert is_override("High/Critical", "Low") and is_override("Enhanced", "Standard")   # 0.1 downgrades
    assert not is_override("", "High") and not is_override("Standard", None)


@pytest.mark.parametrize("account,predicted,start,allowed,refused", [
    ("Enterprise", "Standard", "Standard", ["Enhanced", "High", "Critical", "Standard"], ["Low"]),
    ("Enterprise", "High/Critical", "High", ["Critical", "High"], ["Low", "Standard", "Enhanced"]),
    ("Personal", "Low", "Low", ["Standard", "Enhanced", "Low"], ["High", "Critical"]),
    ("Personal", "Enhanced", "Enhanced", [], ["Low", "Standard", "High", "Critical"])])
def test_raise_level_is_upward_only_and_account_bound(account, predicted, start, allowed, refused):
    d = SecurityDecision(FINAL, account, predicted=predicted, level=start)
    for lv in refused:
        with pytest.raises(ValueError):
            d.raise_level(lv)
        assert d.level == start
    for lv in allowed:                                       # may go back down to the prediction
        d.raise_level(lv)
        assert d.level == lv


def test_raise_level_needs_a_final_level():
    with pytest.raises(ValueError):
        SecurityDecision(CHOICE_REQUIRED, "Enterprise", predicted="High/Critical").raise_level("Critical")


def test_needs_ack_for_low_confidence_or_enhanced():
    assert SecurityDecision(FINAL, "Personal", predicted="Enhanced", level="Enhanced", confidence=0.99).needs_ack
    assert SecurityDecision(FINAL, "Personal", predicted="Low", level="Low", confidence=0.69).needs_ack
    assert not SecurityDecision(FINAL, "Personal", predicted="Low", level="Low", confidence=0.70).needs_ack


def test_personal_unsupported_suggests_enterprise_and_no_quantum_claims(engine, params_by_class):
    d = engine.decide("x.txt", "Personal", params_by_class["High/Critical"])
    assert "Enterprise vault" in d.message
    text = str(HIGH_CRITICAL_OPTIONS).lower()
    assert "ml-kem-1024" in text and "chacha20-poly1305" in text and "quantum" not in text


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
    vault = new_vault(tmp_path / "DEDV")
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
