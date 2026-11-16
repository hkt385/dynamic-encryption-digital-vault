import itertools

import pytest

from services.ml_model_service import (CLASS_LABELS, FEATURES, MLModelService, ModelError,
                                       ModelInputError)


def test_model_loads_with_expected_schema(model):
    assert sorted(model.classes) == sorted(CLASS_LABELS)
    assert set(FEATURES) <= set(model._input_columns)
    for f in FEATURES:
        assert model.options(f)


def test_defaults_are_valid(model):
    assert model.validate(model.default_parameters()) == model.default_parameters()


def test_all_four_classes_are_producible(params_by_class):
    assert set(params_by_class) == set(CLASS_LABELS)


def test_label_matches_sklearn_predict(model):
    import pandas as pd
    combos = list(itertools.islice(itertools.product(*[model.options(f) for f in FEATURES]), 0, 40000, 397))
    blank = {k: "" for k in model._input_columns if k not in FEATURES}
    X = pd.DataFrame([{**dict(zip(FEATURES, c)), **blank} for c in combos], columns=model._input_columns)
    expected = model._model.predict(X)
    got = [model.predict(dict(zip(FEATURES, c))).label for c in combos]
    assert list(expected) == got


def test_unused_training_columns_do_not_affect_output(model):
    """The 3 columns the pipeline drops (Scenario etc.) must not change probabilities."""
    import pandas as pd
    p = model.default_parameters()
    base = model.predict(p).probabilities
    row = {c: p.get(c, "") for c in model._input_columns}
    row.update({"Scenario": "3", "Respondent Type": "Other", "Digital Document Handling Frequency": "Rarely"})
    proba = model._model.predict_proba(pd.DataFrame([row], columns=model._input_columns))[0]
    assert [round(x, 12) for x in proba] == [round(base[c], 12) for c in model.classes]


@pytest.mark.parametrize("bad", [
    {"Sensitivity": "Extreme"},               # unknown value
    {"Sensitivity": None},
    {"Protection Duration": "1-5 years"},     # ASCII hyphen instead of the model's en dash
])
def test_invalid_values_rejected(model, bad):
    with pytest.raises(ModelInputError):
        model.predict({**model.default_parameters(), **bad})


def test_missing_and_extra_parameters_rejected(model):
    p = model.default_parameters()
    p.pop("Sensitivity")
    with pytest.raises(ModelInputError, match="Missing"):
        model.predict(p)
    with pytest.raises(ModelInputError, match="Unknown"):
        model.predict({**model.default_parameters(), "Scenario": "1"})


def test_missing_model_file_gives_clear_error(tmp_path):
    with pytest.raises(ModelError, match="not found"):
        MLModelService(tmp_path / "nope.joblib")


def test_corrupt_model_file_gives_clear_error(tmp_path):
    f = tmp_path / "m.joblib"
    f.write_bytes(b"not a model")
    with pytest.raises(ModelError, match="could not be loaded"):
        MLModelService(f)
