"""Smoke run of bench/benchmark.py: every level and output file, sane statistics."""
import csv
import importlib.util
import json
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent / "bench" / "benchmark.py"


def test_quick_benchmark_writes_all_results(tmp_path):
    spec = importlib.util.spec_from_file_location("dedv_benchmark", BENCH)
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    assert bench.main(["--quick", "--out", str(tmp_path)]) == 0
    for name in ("raw.csv", "summary.csv", "environment.json", "time_vs_size.pdf", "time_vs_size.png",
                 "overhead.pdf", "overhead.png"):
        assert (tmp_path / name).stat().st_size > 0, name
    rows = list(csv.DictReader(open(tmp_path / "summary.csv", encoding="utf-8")))
    enc = [r for r in rows if r["kind"] == "encryption"]
    assert len(enc) == 5 * 1 * 4                                   # levels x quick sizes x (path, op)
    for r in rows:
        assert float(r["q1_s"]) <= float(r["median_s"]) <= float(r["q3_s"])
    assert {r["kind"] for r in rows} == {"encryption", "model", "kdf"}
    assert all(int(r["file_overhead_bytes"]) == 28 for r in enc)   # 12-byte nonce + 16-byte tag
    e2e = {r["level"]: int(r["key_record_bytes"]) for r in enc if r["path"] == "end_to_end"}
    assert e2e["Enhanced"] > e2e["Critical"] > e2e["Standard"] > e2e["Low"]
    env = json.loads((tmp_path / "environment.json").read_text())
    assert env["ram_bytes"] and env["packages"]["cryptography"] and env["argon2id"]["time_cost"]
