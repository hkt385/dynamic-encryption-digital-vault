# Building and testing DEDV

## Environment (Windows)

Python **3.13** (scikit-learn 1.6.1 has no build for 3.14):

```
py -3.13 -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
```

`scikit-learn` must stay at **1.6.1**: `model/final_model.joblib` was pickled with it.
[Inno Setup 6/7](https://jrsoftware.org/isdl.php) is needed only for the installer step.

## Run from source

```
python dedv\main.py
```

## Tests

```
python -m pytest tests -q
```

Qt tests run offscreen; no display needed. Tests use temporary vaults and a tiny Argon2id cost and never touch
your real vault, key folder or settings.

## Benchmarks

```
python bench\benchmark.py
```

About 6 minutes; writes `bench\results\`. See `bench\README.md`.

## Build the application and installer

From the activated venv:

```
build.bat
```

* `dist\DEDV\DEDV.exe` - the packaged app (model is bundled under `_internal\model\`).
* `installer\DEDV_Setup.exe` - the Inno Setup installer (exit code 2 and a notice if Inno Setup is missing).
* The build fails if a key, settings or vault database file (`DEDV_key.txt`, `wrapped_keys.json`,
  `dev_keys.json`, `settings.json`, `keys.db`, `vault.db`) ends up under `dist`.

## Verify a packaged build

```
set DEDV_SELFTEST_PASSWORD=<a throwaway passphrase of at least 12 characters>
start /wait dist\DEDV\DEDV.exe --selftest result.json
echo %errorlevel%
```

Loads the model, then runs the whole vault flow in a temporary folder (password, lock/unlock, one file per
level, read back, re-encrypt, `release_key` refused while locked, audit chain) and writes the result per check
to `result.json`; exit code 0 = all passed. The password is read only from the environment. The same command
works against the installed `DEDV.exe`. Details: `docs/DEVELOPER_INSTRUCTIONS.md`, section E.

## Where things live

| What | Where |
|---|---|
| Model (read-only) | `model/final_model.joblib` -> `<install>\_internal\model\` |
| Model training notes | Kept with the model's training project (not in this repository) |
| Vault | `<chosen folder>\DEDV\` (`encrypted_files\`, `metadata\vault.db`, `config\keys.db`) |
| Settings incl. dropdown selections | `%APPDATA%\DEDV\settings.json` (outside the install dir) |
| Window geometry | Windows registry via `QSettings("DEDV", "DEDV")` |
