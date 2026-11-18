# DEDV benchmarks

`benchmark.py` measures what each security level costs, for the paper. It runs entirely in a
temporary folder; your vault, key folder and settings are never touched.

```bat
:: from the repository root, with the project venv (Python 3.13, requirements.txt installed)
.venv\Scripts\python.exe bench\benchmark.py                 :: full run, about 6 minutes
.venv\Scripts\python.exe bench\benchmark.py --quick --out %TEMP%\dedv-bench   :: smoke run
```

Close other programs first: the timings are wall-clock times on a normal desktop.

## What is measured

For each of the 5 levels (Low, Standard, Enhanced, High, Critical) and each file size
(1 KB, 100 KB, 1 MB, 10 MB, 50 MB; seeded random data, seed in `environment.json`):

| Path | Encrypt | Decrypt |
|---|---|---|
| `primitive` | `EncryptionService` in memory, **including the per-file key generation the level needs** (RSA-4096 key pair for Enhanced, ML-KEM-1024 key pair for Critical) | `EncryptionService.decrypt_bytes` from a ciphertext file that is in the OS page cache and was opened once before (see Limits), including loading the RSA / ML-KEM private key |
| `end_to_end` | `VaultService.store_files`: read the source file, encrypt, write the ciphertext, seal the key record under the Vault Master Key, insert the metadata and audit rows (one SQLite transaction) | `VaultService.read_file`: `release_key` (authorization check, unwrap, audit row) then decrypt, then the `read` audit row |

Also:

- **Size overhead**: ciphertext file size minus plaintext size, and the size of the sealed key
  record in `keys.db` (nonce + AES-GCM ciphertext of the key material). Both are independent of
  the file size.
- **Peak memory**: the peak of the Python heap during one call, with `tracemalloc`, in a separate
  pass (tracemalloc slows the timed runs). Buffers allocated inside OpenSSL are not included.
- **Model inference**: one `SecurityDecisionEngine.decide()` call, as the Upload page makes it
  (validate the 7 inputs, `predict_proba`, account rules); 100 repetitions.
- **Argon2id unlock**: `AuthSession.unlock()` (Argon2id derivation + unwrapping the VMK) with the
  parameters the vault stores; recorded in `environment.json`.

Every measurement: warm-up runs (2), then 20 timed repetitions; reported as median and
interquartile range (IQR, `statistics.quantiles(..., method="inclusive")`). The garbage collector
is collected before and disabled during each timed call. Each repetition runs all five levels in
an order rotated per repetition, so every level runs first equally often: measuring one level
after another made whichever level ran first at a size look up to 1.5x slower.

## Limits

- **Whole files are loaded into memory** by DEDV (encryption, decryption and preview all work on
  `bytes`), so the measured sizes stop at 50 MB on purpose. Peak memory is about 2-3x the file size.
- End-to-end times include SQLite commits with `fsync` (WAL mode). For small files this, not the
  cipher, dominates; a read commits twice (key release audit + read audit).
- With Windows Defender real-time protection on (as on the reference machine), the first open of a
  newly written file costs about 8 ms (antivirus scan; a second open of a 1 KB file takes 0.2 ms).
  End-to-end reads include this cost, because each one reads a file stored moments earlier. The
  primitive decryption opens the file once, untimed, before it is timed, so it measures the
  cryptography only.
- RSA-4096 key generation time varies a lot between runs (random prime search); look at the IQR.
- Enhanced reads cost about 0.3 s at every size. A separate check on the reference machine (10 runs,
  median) split it up: loading the RSA-4096 private key with `load_der_private_key` 281 ms (the
  library validates the key on every load), RSA-OAEP decryption 1.8 ms; key generation 584 ms.
- One machine, one run. The vault lives on the same disk as `%TEMP%`.

## Output (`results/`)

| File | Content |
|---|---|
| `raw.csv` | one row per timed repetition: `kind, level, algorithm, size_bytes, path, op, rep, seconds` |
| `summary.csv` | median, Q1, Q3, IQR, MB/s, file and key-record overhead (bytes and % of the plaintext), peak Python heap |
| `environment.json` | CPU, RAM, OS, Python, OpenSSL and package versions, git commit, Argon2id parameters, seed |
| `time_vs_size.pdf/.png` | time vs file size per level, log-log; 4 panels (primitive / end to end x encrypt / decrypt) |
| `overhead.pdf/.png` | bytes stored per file in addition to the plaintext, per level |

`kind` is `encryption`, `model` or `kdf`. In `summary.csv`, `key_record_bytes` is only filled for
the `end_to_end` rows (the primitive path stores no key record).
