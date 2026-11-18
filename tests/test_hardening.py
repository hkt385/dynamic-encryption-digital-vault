"""Phase 4: temporary plaintext copies and the --selftest flow."""
import json
import os
import sys
import time

import pytest

from conftest import PASSWORD
from services import viewer_service
from services.viewer_service import STALE_AFTER_SECONDS, TempFiles


@pytest.fixture
def temp(tmp_path):
    return TempFiles(tmp_path / "tmpview")


def test_cleanup_overwrites_before_deleting(temp, monkeypatch):
    wiped = []
    real = viewer_service.wipe_and_delete
    monkeypatch.setattr(viewer_service, "wipe_and_delete", lambda p: (wiped.append(p.read_bytes()), real(p)))
    path = temp.write("secret.docx", b"plaintext")
    assert temp.cleanup() == [] and not path.parent.exists()
    assert wiped == [b"plaintext"]          # the renamed copy went through the zero-overwrite


@pytest.mark.skipif(sys.platform != "win32", reason="Windows refuses to rename a file another handle has open")
def test_copy_in_use_is_skipped_not_zeroed(temp):
    path = temp.write("report.xyz", b"plaintext")
    with open(path, "rb"):                  # another program still has it open
        assert temp.cleanup() == [path.parent]
        assert temp.sweep_stale() == 0
        assert path.read_bytes() == b"plaintext"
    assert temp.cleanup() == [] and not path.parent.exists()


def test_periodic_sweep_removes_only_old_copies(temp):
    fresh = temp.write("a.xyz", b"1")
    old = temp.write("b.xyz", b"2")
    past = time.time() - STALE_AFTER_SECONDS - 1
    os.utime(old.parent, (past, past))
    assert temp.sweep_stale(STALE_AFTER_SECONDS) == 1
    assert fresh.exists() and not old.parent.exists()
    assert temp.cleanup() == [] and not fresh.exists()


def test_startup_sweep_removes_leftovers_of_earlier_runs(temp, tmp_path):
    temp.write("left.xyz", b"x")
    assert TempFiles(tmp_path / "tmpview").sweep_stale() == 1
    assert not any((tmp_path / "tmpview").iterdir())


# ---- --selftest ------------------------------------------------------------------------------------------
def test_selftest_needs_the_password_env_var(tmp_path, monkeypatch):
    from main import selftest
    monkeypatch.delenv("DEDV_SELFTEST_PASSWORD", raising=False)
    out = tmp_path / "r.json"
    assert selftest(str(out)) == 1
    result = json.loads(out.read_text())
    assert not result["ok"] and "DEDV_SELFTEST_PASSWORD" in result["error"]


def test_selftest_runs_the_full_vault_flow(tmp_path, monkeypatch):
    from main import selftest
    monkeypatch.setenv("DEDV_SELFTEST_PASSWORD", PASSWORD)
    out = tmp_path / "r.json"
    assert selftest(str(out)) == 0, out.read_text()
    result = json.loads(out.read_text())
    flow = result["vault_flow"]
    assert set(flow["checks"]) == {"unlock", "store_every_level", "read_back", "reencrypt",
                                   "locked_refuses_key", "audit_chain", "session"}
    assert all(flow["checks"].values()) and len(set(flow["algorithms"].values())) == 5
    assert PASSWORD not in out.read_text()
