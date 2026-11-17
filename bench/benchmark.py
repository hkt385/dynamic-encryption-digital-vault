"""DEDV benchmarks for the paper. See bench/README.md for what is measured and how to read it.

From the repository root, with the project venv:
    .venv\\Scripts\\python.exe bench\\benchmark.py               # full run -> bench/results/
    .venv\\Scripts\\python.exe bench\\benchmark.py --quick --out <dir>   # smoke run

Everything runs in a temporary folder; the user's vault, key folder and settings are never used.
"""
import argparse
import csv
import gc
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for p in (ROOT / "encryption", ROOT / "dedv"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

LEVELS = ("Low", "Standard", "Enhanced", "High", "Critical")
SIZES = (1024, 100 * 1024, 1024 ** 2, 10 * 1024 ** 2, 50 * 1024 ** 2)
SIZE_LABELS = {1024: "1 KB", 100 * 1024: "100 KB", 1024 ** 2: "1 MB", 10 * 1024 ** 2: "10 MB",
               50 * 1024 ** 2: "50 MB"}
SEED = 20261117
PASSWORD = "benchmark passphrase only"     # not a secret: throwaway vault in a temp folder
PACKAGES = ("cryptography", "argon2-cffi", "scikit-learn", "numpy", "pandas", "joblib", "PySide6",
            "matplotlib")

RAW_FIELDS = ("kind", "level", "algorithm", "size_bytes", "path", "op", "rep", "seconds")
SUMMARY_FIELDS = ("kind", "level", "algorithm", "size_bytes", "path", "op", "n", "median_s", "q1_s",
                  "q3_s", "iqr_s", "median_MBps", "file_bytes", "file_overhead_bytes",
                  "file_overhead_pct", "key_record_bytes", "total_overhead_pct", "peak_python_heap_bytes")


# ---- measuring ---------------------------------------------------------------------------------------
def timed(fn, reps: int, warmup: int) -> list[float]:
    """Seconds per call; GC is collected before and disabled during each call (as timeit does)."""
    for _ in range(warmup):
        fn()
    out = []
    for _ in range(reps):
        gc.collect()
        gc.disable()
        try:
            t = time.perf_counter()
            fn()
            out.append(time.perf_counter() - t)
        finally:
            gc.enable()
    return out


def peak_heap(fn) -> int:
    """Peak Python-heap bytes allocated during fn() (tracemalloc; OpenSSL's own buffers are not
    seen). Run separately from the timed runs because tracemalloc slows everything down."""
    gc.collect()
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def quartiles(xs: list[float]) -> tuple[float, float, float]:
    q1, med, q3 = statistics.quantiles(xs, n=4, method="inclusive")
    return q1, med, q3


def summary_row(kind, level, algorithm, size, path, op, times, **extra) -> dict:
    q1, med, q3 = quartiles(times)
    row = dict(kind=kind, level=level, algorithm=algorithm, size_bytes=size, path=path, op=op,
               n=len(times), median_s=med, q1_s=q1, q3_s=q3, iqr_s=q3 - q1,
               median_MBps=(size / 1024 ** 2) / med if size else "")
    row.update(extra)
    return row


# ---- the measurements ------------------------------------------------------------------------------
def bench_encryption(tmp: Path, sizes, reps, warmup, raw, summary, log):
    """Primitive: EncryptionService in memory (includes the per-file key generation the level
    requires); decryption reads the ciphertext from a (page-cached) file.
    End to end through VaultService: store = read the source, encrypt, write, seal the key under
    the VMK, insert metadata + audit row; read = release_key (unwrap + audit) and decrypt.

    Each repetition runs all five levels, in an order rotated per repetition so every level runs
    first equally often (measuring one level after another made the first level of each size look
    slower). Stored ciphertexts are deleted after their read to keep disk use flat."""
    from services.encryption_service import LEVEL_ALGORITHM, EncryptionService
    from services.security_decision_service import ENTERPRISE, FINAL, HIGH_CRITICAL, SecurityDecision
    from services.storage_service import create_vault
    from services.vault_service import VaultService

    enc = EncryptionService()
    vault = VaultService(create_vault(tmp))
    vault.session.initialize(PASSWORD)
    decisions = {lv: SecurityDecision(FINAL, ENTERPRISE, level=lv, acknowledged=True,
                                      predicted=HIGH_CRITICAL if lv in ("High", "Critical") else lv)
                 for lv in LEVELS}
    ops = [(p, o) for p in ("primitive", "end_to_end") for o in ("encrypt", "decrypt")]
    rng = random.Random(SEED)

    def clock(fn) -> float:
        gc.collect()
        gc.disable()
        try:
            t = time.perf_counter()
            fn()
            return time.perf_counter() - t
        finally:
            gc.enable()

    def one_round(level, data, src, measure) -> tuple[dict, int, int]:
        """The four operations for one level; `measure` is clock (seconds) or peak_heap (bytes)."""
        algorithm, prim, box = LEVEL_ALGORITHM[level], tmp / f"{level}.enc", {}

        def encrypt():
            box["blob"], box["res"] = enc._encrypt(algorithm, data)

        def decrypt():
            r = box["res"]
            box["out"] = enc.decrypt_bytes(prim, r.algorithm, r.params, r.secrets)

        def store():
            box["stored"] = vault.store_files([(src, decisions[level])], ENTERPRISE)

        def read():
            box["read"] = vault.read_file(box["meta"].file_id)[1]

        out = {("primitive", "encrypt"): measure(encrypt)}
        prim.write_bytes(box.pop("blob"))
        prim.read_bytes()    # untimed: the first open of a new file pays the antivirus scan (~8 ms)
        out["primitive", "decrypt"] = measure(decrypt)
        assert box.pop("out") == data
        out["end_to_end", "encrypt"] = measure(store)
        assert box["stored"].stored, box["stored"].failed
        meta = box["meta"] = vault.list_files()[-1]
        out["end_to_end", "decrypt"] = measure(read)
        assert box.pop("read") == data
        path = vault.encrypted_dir / meta.encrypted_name
        with vault.db as conn:
            record = conn.execute("SELECT length(nonce) + length(ct) FROM keys.wrapped_keys "
                                  "WHERE token=?", (meta.token,)).fetchone()[0]
        file_bytes = path.stat().st_size
        path.unlink()
        prim.unlink()
        return out, file_bytes, record

    try:
        for size in sizes:
            data = rng.randbytes(size)
            src = tmp / f"src_{size}.bin"
            src.write_bytes(data)
            log(f"{SIZE_LABELS.get(size, size)}")
            times = {(lv, op): [] for lv in LEVELS for op in ops}
            mem, stored = {}, {}
            for i in range(warmup + reps + 1):        # the last round is the memory pass
                k = i % len(LEVELS)
                for level in LEVELS[k:] + LEVELS[:k]:
                    if i == warmup + reps:
                        mem[level], *stored[level] = one_round(level, data, src, peak_heap)
                    else:
                        res, *stored[level] = one_round(level, data, src, clock)
                        if i >= warmup:
                            for op in ops:
                                times[level, op].append(res[op])
            for level in LEVELS:
                algorithm = LEVEL_ALGORITHM[level]
                file_bytes, record = stored[level]
                over = file_bytes - size
                info = dict(file_bytes=file_bytes, file_overhead_bytes=over,
                            file_overhead_pct=100 * over / size, key_record_bytes=record,
                            total_overhead_pct=100 * (over + record) / size)
                for path_, op in ops:
                    t = times[level, (path_, op)]
                    raw += [dict(kind="encryption", level=level, algorithm=algorithm, size_bytes=size,
                                 path=path_, op=op, rep=n, seconds=s) for n, s in enumerate(t)]
                    extra = dict(info, peak_python_heap_bytes=mem[level][path_, op])
                    if path_ == "primitive":
                        extra["key_record_bytes"] = extra["total_overhead_pct"] = ""
                    summary.append(summary_row("encryption", level, algorithm, size, path_, op, t,
                                               **extra))
            src.unlink()
    finally:
        vault.close()


def bench_model(reps, warmup, raw, summary, log):
    """One prediction as the Upload page makes it: validate, predict_proba, account rules."""
    from services.ml_model_service import get_model_service
    from services.security_decision_service import SecurityDecisionEngine
    log("model inference")
    engine = SecurityDecisionEngine(get_model_service())
    params = engine.model.default_parameters()
    times = timed(lambda: engine.decide(Path("x.txt"), "Enterprise", params), reps, warmup)
    raw += [dict(kind="model", path="in_memory", op="predict", rep=k, seconds=s) for k, s in enumerate(times)]
    summary.append(summary_row("model", "", "RandomForest (final_model.joblib)", 0, "in_memory",
                               "predict", times))


def bench_unlock(tmp: Path, reps, warmup, raw, summary, log) -> dict:
    """Unlock = Argon2id key derivation + unwrapping the VMK, with the parameters the vault stores."""
    from services import auth_service
    from services.storage_service import create_vault
    from services.vault_service import VaultService
    log("argon2id unlock")
    vault = VaultService(create_vault(tmp))
    try:
        vault.session.initialize(PASSWORD)
        with vault.db as conn:
            row = conn.execute("SELECT time_cost, memory_kib, parallelism FROM keys.vault_keys "
                               "WHERE slot=?", (auth_service.PASSWORD_SLOT,)).fetchone()
        params = dict(time_cost=row[0], memory_kib=row[1], parallelism=row[2])

        def unlock():
            vault.lock()
            vault.session.unlock(PASSWORD)
        times = timed(unlock, reps, warmup)
    finally:
        vault.close()
    algorithm = f"Argon2id t={params['time_cost']} m={params['memory_kib'] // 1024} MiB p={params['parallelism']}"
    raw += [dict(kind="kdf", algorithm=algorithm, path="unlock", op="unlock", rep=k, seconds=s)
            for k, s in enumerate(times)]
    summary.append(summary_row("kdf", "", algorithm, 0, "unlock", "unlock", times))
    return params


# ---- environment -----------------------------------------------------------------------------------
def _cpu_name() -> str:
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                return winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
        except OSError:
            pass
    return platform.processor() or platform.machine()


def _ram_bytes() -> int | None:
    if os.name == "nt":
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(status)
        return status.ullTotalPhys if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)) else None
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return None


def environment(args, argon2: dict) -> dict:
    from cryptography.hazmat.backends.openssl import backend
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        commit = ""
    versions = {}
    for p in PACKAGES:
        try:
            versions[p] = metadata.version(p)
        except metadata.PackageNotFoundError:
            versions[p] = None
    return {"timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "git_commit": commit, "os": platform.platform(), "cpu": _cpu_name(),
            "logical_cpus": os.cpu_count(), "ram_bytes": _ram_bytes(),
            "python": sys.version.split()[0], "openssl": backend.openssl_version_text(),
            "packages": versions, "argon2id": argon2, "seed": SEED, "sizes_bytes": list(args.sizes),
            "repetitions": args.reps, "warmup_runs": args.warmup,
            "timer": "time.perf_counter, GC disabled during each timed call"}


# ---- plots -----------------------------------------------------------------------------------------
# Categorical slots 1-5 of the reference palette (validated: adjacent CVD dE >= 9.1, normal-vision
# dE >= 19.6). Three slots are below 3:1 contrast on white, so every level also has its own marker
# and the numbers are in summary.csv.
LEVEL_STYLE = {"Low": ("#2a78d6", "o"), "Standard": ("#eb6834", "s"), "Enhanced": ("#1baf7a", "^"),
               "High": ("#eda100", "D"), "Critical": ("#e87ba4", "v")}
INK, INK_2, GRID, AXIS = "#0b0b0b", "#52514e", "#e1e0d9", "#c3c2b7"


def _style(ax):
    ax.grid(True, which="major", color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(AXIS)
    ax.tick_params(colors=INK_2, labelsize=8)


def plot(summary: list[dict], out: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "sans-serif", "font.size": 9, "text.color": INK,
                         "axes.labelcolor": INK_2, "pdf.fonttype": 42})
    rows = [r for r in summary if r["kind"] == "encryption"]
    sizes = sorted({r["size_bytes"] for r in rows})

    fig, axes = plt.subplots(2, 2, figsize=(7.2, 5.6), sharex=True)
    panels = (("primitive", "encrypt", "Primitive: encrypt"), ("primitive", "decrypt", "Primitive: decrypt"),
              ("end_to_end", "encrypt", "End to end: store"), ("end_to_end", "decrypt", "End to end: read"))
    for ax, (path, op, title) in zip(axes.flat, panels):
        _style(ax)
        for level in LEVELS:
            pts = sorted((r for r in rows if r["level"] == level and r["path"] == path and r["op"] == op),
                         key=lambda r: r["size_bytes"])
            x = [r["size_bytes"] for r in pts]
            color, marker = LEVEL_STYLE[level]
            ax.fill_between(x, [r["q1_s"] for r in pts], [r["q3_s"] for r in pts], color=color,
                            alpha=0.18, linewidth=0)
            ax.plot(x, [r["median_s"] for r in pts], color=color, marker=marker, markersize=4.5,
                    linewidth=1.5, label=level, markeredgecolor="white", markeredgewidth=0.6)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_title(title, fontsize=9, color=INK, loc="left")
        ax.set_xticks(sizes, [SIZE_LABELS.get(s, str(s)) for s in sizes])
        ax.minorticks_off()
    for ax in axes[:, 0]:
        ax.set_ylabel("Time (s)")
    for ax in axes[1, :]:
        ax.set_xlabel("File size")
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=5, frameon=False, fontsize=8)
    fig.text(0.5, 0.005, "Lines: median; bands: interquartile range. Log-log axes.",
             ha="center", fontsize=7, color=INK_2)
    fig.tight_layout(rect=(0, 0.02, 1, 0.95))
    for ext in ("pdf", "png"):
        fig.savefig(out / f"time_vs_size.{ext}", dpi=200)
    plt.close(fig)

    # Storage overhead per level (size-independent, so taken at the largest size).
    big = max(sizes)
    per = {r["level"]: r for r in rows if r["size_bytes"] == big and r["path"] == "end_to_end"
           and r["op"] == "encrypt"}
    fig, ax = plt.subplots(figsize=(5.2, 2.8))
    _style(ax)
    ax.grid(False, axis="y")
    y = list(range(len(LEVELS)))[::-1]
    files = [per[lv]["file_overhead_bytes"] for lv in LEVELS]
    keys = [per[lv]["key_record_bytes"] for lv in LEVELS]
    ax.barh(y, files, height=0.55, color="#2a78d6", label="Ciphertext file: nonce + tag",
            edgecolor="white", linewidth=1.5)
    ax.barh(y, keys, left=files, height=0.55, color="#eb6834", label="Sealed key record in keys.db",
            edgecolor="white", linewidth=1.5)
    for yi, f, k in zip(y, files, keys):
        ax.text(f + k + max(keys) * 0.015, yi, f"{f + k:,} B", va="center", fontsize=8, color=INK)
    ax.set_yticks(y, LEVELS)
    ax.set_xlabel("Bytes stored per file in addition to the plaintext")
    ax.set_xlim(0, max(f + k for f, k in zip(files, keys)) * 1.18)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2, frameon=False, fontsize=8)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(out / f"overhead.{ext}", dpi=200)
    plt.close(fig)


# ---- main ------------------------------------------------------------------------------------------
def write_csv(path: Path, fields, rows) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, restval="")
        w.writeheader()
        w.writerows(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=ROOT / "bench" / "results")
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--warmup", type=int, default=2)
    ap.add_argument("--quick", action="store_true", help="smoke run: 1 KB only, 2 repetitions")
    args = ap.parse_args(argv)
    if args.quick:
        args.sizes, args.reps, args.warmup = SIZES[:1], 2, 0
    else:
        args.sizes = SIZES
    if args.reps < 2:
        ap.error("--reps must be at least 2 (quartiles need two values)")
    args.out.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()

    def log(msg):
        print(f"[{time.perf_counter() - start:7.1f} s] {msg}", flush=True)

    raw, summary = [], []
    with tempfile.TemporaryDirectory(prefix="dedv-bench-", ignore_cleanup_errors=True) as tmp:
        tmp = Path(tmp)
        os.environ.setdefault("DEDV_KEY_DIR", str(tmp / "keys"))     # never the real folders
        os.environ.setdefault("DEDV_TEMP_DIR", str(tmp / "tmpview"))
        (tmp / "enc").mkdir()
        (tmp / "kdf").mkdir()
        bench_encryption(tmp / "enc", args.sizes, args.reps, args.warmup, raw, summary, log)
        bench_model(max(args.reps, 100) if not args.quick else args.reps, 5, raw, summary, log)
        argon2 = bench_unlock(tmp / "kdf", args.reps, args.warmup, raw, summary, log)

    write_csv(args.out / "raw.csv", RAW_FIELDS, raw)
    write_csv(args.out / "summary.csv", SUMMARY_FIELDS, summary)
    (args.out / "environment.json").write_text(json.dumps(environment(args, argon2), indent=2),
                                               encoding="utf-8")
    plot(summary, args.out)
    log(f"done: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
