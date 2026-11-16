# Building and testing DEDV

## Environment (Windows)

```
python -m venv .venv && .venv\Scripts\activate
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

(Qt tests run offscreen; no display needed.)

## Build the application and installer

```
build.bat
```

* `dist\DEDV\DEDV.exe` - the packaged app (model is bundled under `_internal\model\`).
* `installer\DEDV_Setup.exe` - the Inno Setup installer (exit code 2 and a notice if Inno Setup is missing).

## Verify a packaged build

```
dist\DEDV\DEDV.exe --selftest result.json
```

Writes `result.json` containing the model path, class list and a sample prediction, then exits
(0 = model loaded and predicted, 1 = failed, with the error in the file). The same command works
against the installed `DEDV.exe`.

## Where things live

| What | Where |
|---|---|
| Model (read-only) | `model/final_model.joblib` -> `<install>\_internal\model\` |
| Model documentation | `CONTEXT_PROMPT.md` (development only, not bundled) |
| Settings incl. dropdown selections | `%APPDATA%\DEDV\settings.json` (outside the install dir) |
| Window geometry | Windows registry via `QSettings("DEDV", "DEDV")` |
