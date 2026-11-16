import itertools
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "dedv"))

from services.ml_model_service import FEATURES, get_model_service  # noqa: E402


@pytest.fixture(scope="session")
def model():
    return get_model_service()


@pytest.fixture(scope="session")
def params_by_class(model):
    """Highest-confidence valid parameter set for each class (one batched pass over all inputs)."""
    import numpy as np
    import pandas as pd
    combos = list(itertools.product(*[model.options(f) for f in FEATURES]))
    X = pd.DataFrame(combos, columns=list(FEATURES))
    for c in model._input_columns:
        if c not in X:
            X[c] = ""
    P = model._model.predict_proba(X[model._input_columns])
    best = {}
    for j, cls in enumerate(model._model.classes_):
        i = int(np.argmax(np.where(P.argmax(1) == j, P[:, j], -1)))
        if P[i].argmax() == j:
            best[str(cls)] = dict(zip(FEATURES, combos[i]))
    return best


@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    """No test may touch the real DEDV key or temp-view folders."""
    monkeypatch.setenv("DEDV_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("DEDV_TEMP_DIR", str(tmp_path / "tmpview"))


def wait_until(cond, timeout=20.0):
    """Process Qt events until cond() is true (worker threads deliver results via signals)."""
    import time
    from PySide6.QtWidgets import QApplication
    end = time.time() + timeout
    while time.time() < end:
        QApplication.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False
