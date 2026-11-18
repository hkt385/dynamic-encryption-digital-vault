import itertools
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# Safety net under the per-test fixture below: even if a test drops its monkeypatches, the old
# key folder and the temp-view folder can never resolve to the user's real ones.
import tempfile  # noqa: E402
_session_dir = tempfile.mkdtemp(prefix="dedv-tests-")
os.environ["DEDV_KEY_DIR"] = os.path.join(_session_dir, "keys")
os.environ["DEDV_TEMP_DIR"] = os.path.join(_session_dir, "tmpview")
os.environ["DEDV_SESSION_DIR"] = os.path.join(_session_dir, "sessions")
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
    """No test may touch the real DEDV key, temp-view or session folders."""
    monkeypatch.setenv("DEDV_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("DEDV_TEMP_DIR", str(tmp_path / "tmpview"))
    monkeypatch.setenv("DEDV_SESSION_DIR", str(tmp_path / "sessions"))


@pytest.fixture(autouse=True)
def no_vault_acl(monkeypatch):
    """Opening a vault restricts its folder to the current Windows user (icacls). Stubbed here:
    one subprocess per vault open would slow the suite. test_sessions.py tests the real call."""
    from services import vault_service
    monkeypatch.setattr(vault_service, "restrict_permissions", lambda path: True, raising=False)


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Argon2id at its smallest cost: the suite creates hundreds of vaults. The real cost is
    measured by bench/benchmark.py and exercised by --selftest."""
    from services import auth_service
    monkeypatch.setattr(auth_service, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(auth_service, "ARGON2_MEMORY_KIB", 8)
    monkeypatch.setattr(auth_service, "ARGON2_PARALLELISM", 1)


PASSWORD = "correct horse battery"


def new_vault(vault_dir, password=PASSWORD):
    """A new vault with a password set, unlocked. vault.recovery_key holds its recovery key."""
    from services.vault_service import VaultService
    vault = VaultService(vault_dir)
    vault.recovery_key = vault.session.initialize(password)
    return vault


def db_bytes(vault_dir) -> bytes:
    """Raw bytes of both vault databases (and their WAL files), for 'no secret on disk' checks."""
    vault_dir = Path(vault_dir)
    return b"".join(p.read_bytes() for d in ("metadata", "config") for p in (vault_dir / d).glob("*.db*")
                    if not p.name.endswith("-shm"))


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
