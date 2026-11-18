# DEDV Developer Instructions (version 0.3.0)

This document describes what is **actually implemented** in this repository, where data lives, and what
is not done. It is shown in the app (Developer page) and lives at `docs/DEVELOPER_INSTRUCTIONS.md`.
Status words: **Verified** = covered by an automated test or a recorded manual run;
**Implemented, not verified** = code exists but was not exercised; **Not done** = not implemented.

## A. Architecture

| Area | Where | Notes |
|---|---|---|
| Frontend | PySide6 (Qt 6) desktop app, `dedv/ui/` | Entry point `dedv/main.py`; main window `dedv/ui/main_window.py` |
| Pages | `view_page.py`, `upload_page.py`, `edit_page.py`, `settings_page.py`, `developer_page.py` | Navigation order: View, Upload, Edit, Settings, Developer |
| Unlock / password dialogs | `dedv/ui/unlock_dialog.py` | `open_vault()` is the only way the UI opens a vault: first password, upgrade of a 0.1 vault, or unlock |
| Shared loading component | `dedv/ui/loading_overlay.py` | `LoadingOverlay` + `TaskRunner`, used by Upload and Edit |
| Look (Windows 11) | `dedv/ui/styles.py`, `dedv/ui/widgets.py`, `dedv/ui/backdrop.py`, `dedv/ui/icons_rc.py` | Follows the Windows light/dark setting (live); fixed Windows-blue accent; Segoe UI Variable + Segoe Fluent Icons. `widgets.py`: side-bar buttons, `InfoBar` messages, page header, Settings rows, light-theme card shadows (`elevate()`), page entrance (`enter()`). Drop-down chevrons are PNGs in `dedv/ui/icons/`, compiled into `icons_rc.py` (`pyside6-rcc dedv/ui/icons/icons.qrc -o dedv/ui/icons_rc.py`) |
| Materials and motion | `dedv/ui/backdrop.py`, `styles.motion()` | Windows 11 22H2+: Mica behind the main window, Acrylic behind our dialogs (DWM; a window must call `backdrop.prepare(self)` in its constructor). `DEDV_NO_MICA=1` switches materials off. Collapsible side bar (state in QSettings `navCompact`), sliding selection pill, hover fades, page entrance, overlay fade: Fluent timings 83/167/250 ms and `cubic-bezier(0, 0, 0, 1)`; opacity and position only. Animations follow Windows "Animation effects" (off = none) and are off in tests unless a test turns them on |
| Services | `dedv/services/` (plain Python, no HTTP API) | The UI calls `VaultService`; see the table below |
| ML model | `model/final_model.joblib` | Loaded once by `services/ml_model_service.py`; training notes in `CONTEXT_PROMPT.md` |
| Encryption implementations | `encryption/aes.py`, `chacha.py`, `rsa.py`, `mlkem.py` | `ecc.py` exists but is **not mapped** to any level and not used |
| Paths | `dedv/paths.py` | Works from source and when frozen (PyInstaller) |
| Build / installer | `DEDV.spec`, `DEDV.iss`, `build.bat` | Section E |
| Benchmarks | `bench/benchmark.py`, `bench/README.md`, `bench/results/` | Section G |
| Paper and report | Not in git (kept by the team) | Local `report/` folder; `REPORT_CHANGES.md` there explains the files |

| Service | Responsibility |
|---|---|
| `vault_service.VaultService` | Facade: `store_files`, `read_file`, `reencrypt`, `migrate`, `lock`, `close`. Re-checks every rule the UI applies |
| `security_decision_service` | Prediction + account rules + upward-only override (`SecurityDecision.raise_level`, `needs_ack`, `override`) |
| `auth_service.AuthSession` | Password, recovery key, Argon2id, lock/unlock, failed-attempt delay, `resume()` from a session |
| `session_service` | Sessions bound to the Windows sign-in (`SessionStore`), and every Windows API call they need |
| `key_management_service.KeyManagementService` | Per-file key records; `release_key()` is the **only** way to get a file key |
| `audit_service.AuditLog` | Hash-chained audit log; `verify()` |
| `storage_service` | `VaultDb` (one SQLite connection, `keys.db` attached), `SqliteVaultRepository`, `VaultLock`, schema steps |
| `migration_service` | Upgrade of a DEDV 0.1 vault (JSON + plaintext key file) |
| `encryption_service` | Level -> algorithm map and the five algorithms |
| `viewer_service` | In-memory preview decisions; temporary copies for "open externally" |

### Security level -> algorithm

| Final level | Personal | Enterprise | Algorithm id | Implementation |
|---|---|---|---|---|
| Low | yes | yes | `AES-128-GCM` | `aes.py`, 128-bit key |
| Standard | yes | yes | `AES-256-GCM` | `aes.py`, 256-bit key |
| Enhanced | yes | yes | `AES-256-GCM+RSA-4096-OAEP` | file encrypted with a random AES-256 key; `rsa.py` wraps **only that key** with RSA-4096-OAEP (SHA-256) under a per-file key pair |
| High | no | yes | `CHACHA20-POLY1305` | `chacha.py` |
| Critical | no | yes | `AES-256-GCM+ML-KEM-1024` | `mlkem.py`: ML-KEM-1024 encapsulation -> HKDF-SHA256 -> AES-256-GCM key |

Every file gets fresh random keys and a random 12-byte nonce (the first 12 bytes of each `.enc`); the 16-byte
tag detects tampering. The RSA private key and the ML-KEM seed are stored in the **same sealed key record** as the
rest of the file's key material, so the asymmetric step adds no protection beyond the seal under the vault master
key. **Never describe Critical as "quantum-resistant".**

### Key hierarchy and authorization

* A random 256-bit **Vault Master Key (VMK)** is wrapped twice with AES-256-GCM in `keys.db`: under a key derived
  from the password with **Argon2id (t=6, m=256 MiB, p=4, 16-byte salt; about 0.4 s on the reference PC)** and under a
  random 256-bit **recovery key** (shown once as 13 groups of 4 Base32 characters, never stored). Parameters and
  salt are stored per vault, so a later cost change does not break old vaults. Password change and recovery reset
  re-wrap only the VMK.
* Password rule: at least 12 characters (strength hint shown, no extra library).
* Per-file key record: JSON of the key material, sealed with AES-256-GCM under the VMK, in `keys.wrapped_keys`,
  found by a random 128-bit **token**. AAD = token ‖ file id ‖ algorithm ‖ level, so a record moved to another file or
  a changed algorithm/level is detected. `vault.db` stores only the token.
* `release_key(token, file_id, session, purpose)`: refuses while locked, for an unknown token and for a token of
  another file; writes a `key_release` audit row either way. **Never call it inside a `with db:` block** (its audit row
  must commit even when the surrounding operation fails).
* While unlocked the VMK is held in a `bytearray` that is zeroed on lock (best effort in Python).
* Failed unlocks: 3 free attempts, then 2, 4, 8 … s, capped at 5 min, persisted in `keys.unlock_state`. Nothing is
  ever deleted because of failed attempts.
* Auto-lock after idle time (default 10 min, Settings), Lock vault button (side bar). Locking erases the VMK, closes viewers and
  dialogs, removes temporary copies, **ends the session** (below) and asks for the password again.
* One DEDV process per vault: `config\vault.lock` held with an OS lock (`msvcrt.locking`).

### Sessions (Windows sign-in)

* Every password unlock (also first password, upgrade, recovery reset) starts a **session** for the current Windows
  sign-in: a random 256-bit session key wraps the VMK with AES-256-GCM in `keys.sessions` (one row per computer,
  schema step 2). The session key is kept in `%LOCALAPPDATA%\DEDV\sessions\<hash of the vault path>.bin`
  (16-byte session id + the key encrypted with `CryptProtectMemory(CRYPTPROTECTMEMORY_SAME_LOGON)`). Windows
  discards that encryption key at every restart and only the same sign-in can decrypt it; the AAD names the session
  id, the logon ID (`TokenStatistics.AuthenticationId`) and the computer.
* While the session lives, `open_vault()` opens the vault without the password (`AuthSession.resume()`), also after
  closing and restarting DEDV.
* Windows lock screen (Win+L): the main window registers for `WM_WTSSESSION_CHANGE`. Lock = the vault locks as
  above but the session stays; unlock = the session is resumed, or the password is asked if it has ended.
* Ended by: Lock button, idle auto-lock, password change or reset (all sessions), Windows sign-out or restart
  (the cache can no longer be decrypted; refused and deleted on the next try). Refusals are audited with a reason.
* Vault folder: when a vault is opened, its folder is restricted to the current Windows user (`icacls`, inheritance
  removed, Administrators and SYSTEM removed), so other Windows users cannot open it even with the password.

### Decision flow (Upload) and upward-only override

* Upload page -> answer the 7 questions in "About these files" (saved to settings) -> *Select files* ->
  *Predict security level*. Messages appear in a coloured bar (error / warning / info); a message that applies
  to every selected file is shown once.
* The table shows predicted class, confidence, and a Final level box; a probabilities line shows all classes.
* Final level: any level of the account **at or above** the prediction (High/Critical counts as High). Lower
  levels are disabled with a tooltip. Enterprise High/Critical first asks High or Critical (dialog).
* Personal + High/Critical prediction: no level is assigned; the message suggests an Enterprise vault.
* Confidence < 0.70 or prediction = Enhanced: an acknowledgement tick box must be ticked before *Encrypt* is
  enabled. With the shipped model only High/Critical inputs reach 0.70, so Low/Standard/Enhanced always need it.
* Stored per file: the 7 inputs, predicted level, confidence, final level, override flag, `date_added`
  (= time of the decision). The View page shows them for the selected row.
* Edit page: re-encryption never goes below the stored predicted level; files upgraded from 0.1 without a
  prediction use their current level as the floor. `VaultService` enforces all of this again.

### Audit log

`audit_log` table in `vault.db`: UTC time, action, file id, level, result, detail, `prev_hash`, `hash` where
`hash = SHA-256(prev_hash ‖ canonical row JSON)`. Logged: unlock (OK/FAILED), lock, password set/change,
recovery use, session start/resume/end (resume DENIED with a reason), store, read, open externally, re-encrypt,
key release, migration. Never logs plaintext, keys or
passwords. Developer page: *Verify audit log*. **Limit:** the chain is unkeyed; someone who can write `vault.db`
can rebuild it.

### Re-encryption safety

1. Decrypt in memory. 2. Encrypt to a **new** file name and verify by decrypting it. 3. One transaction: insert the
new key record, switch the file row to the new ciphertext and token, delete the old key record. 4. Delete the old
ciphertext. Any failure before the commit deletes the new file and leaves the original file, key and metadata
untouched; a failure in step 4 leaves a harmless orphan.

## B. Where data lives

| Component | What is stored | Location | Sensitive? |
|---|---|---|---|
| Encrypted files | Ciphertext (`<id>.enc`; after re-encryption `<id>.<tag>.enc`) | `<vault>\encrypted_files\`, `<vault>` = `<chosen folder>\DEDV` | Yes (ciphertext) |
| Metadata + audit | File name/type/size/date, predicted/final level, confidence, override, 7 inputs, algorithm, token; audit log | `<vault>\metadata\vault.db` (SQLite, WAL) | File names and inputs may be sensitive |
| Keys | Wrapped VMK (password and recovery slots, Argon2id parameters, salt), sealed per-file key records, failed-unlock state, session rows (VMK wrapped under a session key) | `<vault>\config\keys.db` | Useless without the password, the recovery key or a live session; **back it up with the vault** |
| Session cache | Session id + session key encrypted for the current Windows sign-in (until restart) | `%LOCALAPPDATA%\DEDV\sessions\<hash>.bin` (env `DEDV_SESSION_DIR`) | Opens the vault for this sign-in only; deleted on Lock / when refused |
| Lock file | Empty; held locked while a DEDV process has the vault open | `<vault>\config\vault.lock` | No |
| Upgrade backup | Copy of a 0.1 vault's JSON index and wrapped-key store before the upgrade (the plaintext `dev_keys.json` copy is wiped after a full upgrade) | `<vault>\backup\pre-0.2-<UTC time>\` | The old `wrapped_keys.json` is protected only by the old key file |
| Settings | username, account type, directories, `model_parameters`, `auto_lock_minutes` | `%APPDATA%\DEDV\settings.json` | No keys |
| Window geometry | Qt window size/position | Registry `HKCU\Software\DEDV\DEDV` | No |
| Temporary plaintext | Decrypted copy, only for "open externally" | `%LOCALAPPDATA%\DEDV\tmp\<random>\<name>` (env `DEDV_TEMP_DIR`) | **Highly sensitive** |
| Old key file (0.1) | Plaintext key of 0.1 vaults; read only while upgrading; deleted only when the user confirms | `%LOCALAPPDATA%\DEDV\keys\DEDV_key.txt` (env `DEDV_KEY_DIR`) | **Yes** while it exists |
| ML model | Trained scikit-learn pipeline | `model\final_model.joblib`; installed: `<install dir>\_internal\model\` | No |

Temporary copies: renamed (fails while another program has the file open on Windows, so a file in use is skipped,
never zeroed under that program), overwritten with zeros, flushed and deleted. This happens on lock, on exit, every
60 s for copies older than 5 minutes, and at the next start for leftovers. **Not a secure wipe** on SSDs, journaling
or copy-on-write file systems, or with backup/sync tools.

## C. Implemented versus not done

| Feature | Status |
|---|---|
| Prediction, account rules, upward-only override, acknowledgement | **Verified** (`test_decisions.py`, `test_ui.py`, `test_ui_flows.py`, `test_vault.py`) |
| Five algorithms and the level map | **Verified** (`test_crypto.py`) |
| SQLite storage, transactions, schema steps, cross-process lock (real subprocess) | **Verified** (`test_storage.py`) |
| Password, Argon2id, recovery key, password change, failed-attempt delay | **Verified** (`test_auth.py`, `test_ui_auth.py`) |
| Key tokens, `release_key` refusals (locked / unknown / other file / altered record) | **Verified** (`test_keys.py`) |
| Audit log incl. tamper detection | **Verified** (`test_audit.py`) |
| Upgrade of a 0.1 vault incl. forced mid-way failure and partial upgrade | **Verified** (`test_migration.py`, `test_ui_auth.py`; legacy vaults written by `tests/legacy.py`, cross-checked against the 0.1 code) |
| Lock button, auto-lock, unlock dialog | **Verified** offscreen (`test_ui_auth.py`) |
| Sessions bound to the Windows sign-in: resume, end, refusal after another sign-in / restart / tampering, Win+L lock and unlock | **Verified** (`test_sessions.py` with the real Windows calls; sign-out and restart simulated; `test_ui_auth.py` offscreen). Real Win+L **Implemented, not verified** by a test |
| Owner-only vault folder | **Verified** (`test_sessions.py`, real `icacls` on a temporary folder) |
| Temporary-copy wipe, in-use skip, periodic sweep | **Verified** (`test_hardening.py`) |
| `--selftest` full vault flow | **Verified** from source and from the frozen build (section E) |
| Several users / roles | **Not done** (one password per vault; Personal/Enterprise is a setting, not access control) |
| Hardware-backed key storage (TPM, DPAPI) | **Not done** |
| Keyed or externally anchored audit log | **Not done** |
| Streaming encryption for large files | **Not done** (whole files are loaded into memory) |
| Code-signed installer | **Not done** |

## D. Not done / caveats

* **Single user.** Whoever knows the password (or holds the recovery key) can read everything in the vault.
* **Sessions:** while a session lives, anyone using your signed-in, unlocked Windows account opens the vault
  without the password. Running DEDV once elevated ("Run as administrator") and once normally counts as two
  different sign-ins (the password is asked again).
* **Owner-only folder:** an administrator can still take ownership of the vault folder; FAT32/exFAT drives have
  no permissions, so the restriction is skipped there.
* **Lost password and lost recovery key = lost data.** Nothing can recover the VMK.
* **Best effort only:** zeroing the VMK in memory (Python may keep copies) and wiping temporary copies (see B).
* **Unkeyed audit chain** (see A).
* **Asymmetric levels:** RSA and ML-KEM private keys are stored with the wrapped key, sealed under the VMK.
* **Model reliability:** Enhanced has 8 training records (precision/recall about 0.10); High/Critical ->
  Low/Standard error 15.9 %. See `CONTEXT_PROMPT.md`.
* **Antivirus:** with Windows Defender real-time protection the first open of a newly written file costs about
  8 ms; this shows in small-file read times (`bench/README.md`).
* **Installer** is not signed; Inno Setup must be installed to build it.

## E. Build, install and self-test

Binaries go to `<install dir>` (replaced on upgrade). User data is outside it (section B). `DEDV.iss` has no
`[InstallDelete]`/`[UninstallDelete]` entries, so upgrades, reinstalls and uninstalls do not touch user data.
`build.bat` fails the build if a key file, settings file, `keys.db` or `vault.db` appears under `dist`.

Build (from the repository root, Python 3.13 venv with `pip install -r requirements.txt`; Inno Setup for the
installer):

```
.venv\Scripts\activate
.\build.bat
```

Output: `dist\DEDV\DEDV.exe` and, with Inno Setup, `installer\DEDV_Setup.exe` (exit code 2 = app built, installer
skipped).

Self-test (no UI; exit code 0 = everything passed). It loads the model, then creates a temporary vault, sets the
password, locks, resumes and then ends the Windows sign-in session (in a temporary session folder), unlocks with
the password, stores one file per level, reads them back, re-encrypts one, locks, checks that
`release_key` refuses while locked and verifies the audit chain. The password is read **only** from the
environment variable `DEDV_SELFTEST_PASSWORD` (at least 12 characters), never from the command line:

```
set DEDV_SELFTEST_PASSWORD=<a throwaway passphrase>
start /wait dist\DEDV\DEDV.exe --selftest result.json
echo %errorlevel%
```

(`DEDV.exe` is a windowed program, so `start /wait` is needed for the console to wait and report the exit code.)
To prove that an existing vault is still readable (counts only, nothing is written), add its `...\DEDV` folder; the
same variable must hold that vault's password:

```
start /wait dist\DEDV\DEDV.exe --selftest result.json "D:\Documents\DEDV"
```

**Upgrading from 0.1:** on the first start 0.2 asks for a new password, backs up the old metadata, converts the
vault, verifies every file and shows the recovery key. It then asks whether to delete the old key file
(`DEDV_key.txt`); answer *Keep for now* if another 0.1 vault still needs it (the Developer page has a delete button).

## F. Handover

* **Entry points**: `dedv/main.py`; services in `dedv/services/`; UI in `dedv/ui/`.
* **Test**: `.venv\Scripts\python.exe -m pytest tests -q` (isolated key/temp folders via `conftest.py`; tiny Argon2
  cost; never touches real vaults). Never call `monkeypatch.undo()` in tests.
* **Schema changes**: append a `(version, statements)` step to `storage_service.MIGRATIONS`; never edit a shipped step.
* **Add an algorithm**: module in `encryption/` with `encrypt_bytes/decrypt_bytes`; id and name in
  `encryption_service.py`, a branch in `_encrypt` and `decrypt_bytes`; add it to `LEVEL_ALGORITHM` (and, for a new
  level, to `security_decision_service`); add the module to `hiddenimports` in `DEDV.spec`; add a test in
  `tests/test_crypto.py`. Old files keep working because `algorithm` is stored per file.
* **Loading component**: `TaskRunner.run(fn, on_done, on_error)` shows the overlay before `fn` starts on a worker
  thread; callbacks run on the GUI thread after it is hidden; one task at a time.

## G. Benchmarks

`bench/benchmark.py` measures every level at 1 KB – 50 MB (primitive and end to end), storage overhead, peak
memory, model inference and Argon2id unlock; results, plots and the environment are in `bench/results/`. Method
and limits: `bench/README.md`.
