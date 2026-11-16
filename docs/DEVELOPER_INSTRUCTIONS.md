# DEDV Developer Instructions

This document describes what is **actually implemented** in this repository, where data lives, and what
is left to do. It is shown in the app (Developer page) and lives at `docs/DEVELOPER_INSTRUCTIONS.md`.
Status words: **Verified** = covered by an automated test or a manual run recorded in this document;
**Implemented, not verified** = code exists but was not exercised; **Pending** = not done.

> **The DEDV key is a development stand-in.** It is a plaintext file. Do not ship this key handling to production.

## A. Project architecture

| Area | Where | Notes |
|---|---|---|
| Frontend | PySide6 (Qt 6) desktop app, `dedv/ui/` | Entry point `dedv/main.py`; main window `dedv/ui/main_window.py` |
| Pages | `view_page.py`, `upload_page.py`, `edit_page.py`, `settings_page.py`, `developer_page.py` | Navigation order: View, Upload, Edit, Settings, Developer |
| Shared loading component | `dedv/ui/loading_overlay.py` | `LoadingOverlay` + `TaskRunner`, used by Upload and Edit |
| Backend | Plain Python services in `dedv/services/` (no HTTP API) | The UI calls `VaultService` |
| ML model | `model/final_model.joblib` | Loaded once by `services/ml_model_service.py`; training notes in `CONTEXT_PROMPT.md` |
| Prediction + account rules | `services/security_decision_service.py` | Personal: Low/Standard/Enhanced. Enterprise: also High/Critical, resolved by the user to High or Critical |
| Encryption implementations | `encryption/aes.py`, `chacha.py`, `rsa.py`, `mlkem.py` (`ecc.py` exists but is not mapped to a level) | Flat modules; imported by `services/encryption_service.py` |
| Level -> algorithm mapping | `services/encryption_service.py` (`LEVEL_ALGORITHM`) | See table below |
| Vault orchestration | `services/vault_service.py` | `store_files`, `read_file`, `reencrypt` |
| Metadata | `models/file_metadata.py`, `services/storage_service.py` | JSON index behind the `VaultRepository` interface |
| Keys | `services/key_management_service.py` | DEDV key (KEK) + wrapped per-file secrets |
| Viewing | `services/viewer_service.py`, `ui/file_viewer.py` | In-memory preview; temp files only for external open |
| Paths | `dedv/paths.py` | Works from source and when frozen (PyInstaller) |
| Build / installer | `DEDV.spec` (PyInstaller), `DEDV.iss` (Inno Setup), `build.bat` | See section E |
| Tests | `tests/` (pytest) | `python -m pytest tests -q` |

### Security level -> algorithm (the mapping actually used)

| Final level | Algorithm id | Implementation |
|---|---|---|
| Low | `AES-128-GCM` | `encryption/aes.py`, `generate_key(1)` |
| Standard | `AES-256-GCM` | `encryption/aes.py`, `generate_key(2)` |
| Enhanced | `AES-256-GCM+RSA-4096-OAEP` | `aes.py` encrypts the file with a random AES-256 key; `rsa.py` wraps **only that key** with RSA-4096-OAEP (SHA-256) |
| High | `CHACHA20-POLY1305` | `encryption/chacha.py` (new) |
| Critical | `AES-256-GCM+ML-KEM-1024` | `mlkem.py` (new): ML-KEM-1024 encapsulation -> HKDF-SHA256 -> AES-256-GCM key; file encrypted by `aes.py` |

Notes: ML-KEM is a key-encapsulation mechanism, not a cipher; the file is always encrypted with AES-256-GCM.
The ML-KEM private key (as a 64-byte seed) and the RSA private key are held locally in the wrapped key store,
so in this single-user setup ML-KEM/RSA protect the data key only as well as the DEDV key protects those
private keys. **Do not describe the Critical level as "quantum-resistant" in product claims until a real
key-management design (section D) exists**; today the weakest link is the plaintext DEDV key file.
The nonce (12 bytes) is the first 12 bytes of every `.enc` file; every file gets fresh random keys.

### Workflows

* **Upload**: Upload page -> choose parameters (top of the page, saved to settings) -> Select Files ->
  *Predict Security Level* -> (Enterprise High/Critical: pick High or Critical in the dialog) -> *Encrypt*.
  The overlay ("Encrypting") shows while `VaultService.store_files` runs on a worker thread. The level in the
  final decision is the level used for encryption.
* **Open**: View page, double-click a row -> `VaultService.read_file` decrypts **in memory** -> text/image/PDF
  preview. Executable types are never launched; unknown types are opened externally only after confirmation.
* **Edit / re-encrypt**: Edit page -> pick file and target level -> *Re-encrypt* -> `VaultService.reencrypt`
  (see "Re-encryption safety" below).

### Re-encryption safety

1. Decrypt in memory (no plaintext file). 2. Encrypt to a **new** file name and verify by decrypting it.
3. Store the new secrets under a **new** key reference. 4. Atomically replace the metadata entry.
5. Only then delete the old ciphertext and old key. Any failure before step 4 deletes the new file/key and
leaves the original file, key and metadata untouched. If step 5 fails, an orphaned old file/key remains (harmless,
and listed nowhere). A process-wide lock serialises store/re-encrypt; there is no cross-process lock.

## B. Local storage inventory

| Component | What is stored | Actual location | Sensitive? |
|---|---|---|---|
| ML model | Trained scikit-learn pipeline | Source: `model/final_model.joblib`; installed: `<install dir>\_internal\model\final_model.joblib` | No secret by default |
| Encrypted files | Ciphertext (`<id>.enc`, re-encrypted: `<id>.<tag>.enc`) | `<vault>\encrypted_files\` where `<vault>` = `<chosen folder>\DEDV` (setting `vault_directory`) | Yes |
| Metadata | File name/type/size/date, predicted + final level, `algorithm`, `key_ref`, `enc_params` | `<vault>\metadata\files.json` | May be sensitive (file names) |
| Configuration | username, account type, directories, `model_parameters` (dropdown selections) | `%APPDATA%\DEDV\settings.json` | Depends; contains no keys |
| Window geometry | Qt window size/position | Registry `HKCU\Software\DEDV\DEDV` | No |
| Development key | `DEDV` key-encryption key, 32 random bytes, base64, plaintext | `%LOCALAPPDATA%\DEDV\keys\DEDV_key.txt` (owner-only ACL; override with env `DEDV_KEY_DIR`) | **Yes** |
| Wrapped per-file secrets | Data keys, RSA private key, ML-KEM seed, each sealed with AES-256-GCM under the DEDV key | `<vault>\config\wrapped_keys.json` | Useless without the DEDV key, but keep with backups |
| Legacy plaintext keys | AES-256 keys of files stored before this version | `<vault>\config\dev_keys.json` (entries are removed when the file is re-encrypted) | **Yes** (plaintext) |
| Temporary plaintext | Decrypted copy, only for "open externally" | `%LOCALAPPDATA%\DEDV\tmp\<random>\<name>` (override with env `DEDV_TEMP_DIR`) | **Highly sensitive** |
| Encryption parameters | Nonce: first 12 bytes of each `.enc`. RSA-wrapped AES key (`wrapped_key`) and ML-KEM ciphertext (`kem_ciphertext`): `enc_params` in `files.json`. No salts/IVs are used | see above | Not secret by themselves |

Key-file contents are never written in this document or the tests' output.

## C. Implemented versus pending

| Feature | Status |
|---|---|
| Model prediction, account restrictions (Personal never gets High/Critical; Enterprise must choose High or Critical) | **Verified** (`tests/test_model.py`, `test_decisions.py`, `test_ui.py`). Predictions are unreliable for Enhanced (see `CONTEXT_PROMPT.md`) |
| Upload-page-only parameter dropdowns with persistence | **Verified** (`tests/test_ui_flows.py`) |
| Level -> algorithm mapping and all five algorithms | **Verified** round trips and independent-primitive checks (`tests/test_crypto.py`) |
| Loading animation ("Encrypting") on Encrypt and Re-encrypt | **Verified** headless (visible during work, hidden after success/failure, duplicate clicks refused, GUI timer keeps firing). Visual check of the spinner only via an offscreen screenshot, not by eye on a real display |
| Opening files (double-click), in-memory preview, temp-file handling | **Verified** with stubbed dialogs (`test_ui_flows.py`). Real external applications were not launched in tests |
| Re-encryption on the Edit page incl. rollback | **Verified** (`tests/test_vault.py`, `test_ui_flows.py`) |
| Local DEDV key generation and reuse | **Verified** (`tests/test_keys.py`), owner-only ACL checked on Windows |
| Existing key storage (`KeyManagementService`) | **Reused and changed**: interface kept, secrets now wrapped under the DEDV key. A separate production KEK system does not exist in this repo |
| Real KEK / key hierarchy, rotation, backup, audit | **Pending** (section D) |
| Installer packaging | **Verified** on 2026-10-16 with a *test copy* of `DEDV.iss` (different AppId, per-user, temp folder, so the real install was untouched): installed app loads the model, round-trips all five algorithms, opens a pre-existing 5-file vault (5/5), survives reinstall-over-the-top, uninstall leaves vault and key byte-identical, and launching the installed app created no key. The real `installer\DEDV_Setup.exe` was built but **not** run on this machine (it would upgrade an existing real install). Installer is unsigned |
| Cross-process locking, securely wiping temp files, streaming (large-file) encryption | **Pending** (files are read fully into memory) |
| `ecc.py` (AES-256 + ECC) | Exists, **not mapped** to any level and not used by the app |

## D. Replacing the development key storage

What must be built before production:

1. **Key generation/storage**: use an OS/HSM/KMS-backed store (Windows DPAPI/CNG or a cloud KMS), not a text file.
2. **Identifiers and associations**: `DEDV` is just the id of the current KEK (`kek_id` in `wrapped_keys.json`).
   Add a key registry with versions; today `key_ref` (per file version) points at one wrapped record.
3. **DEK/KEK separation**: already present in shape: per-file data keys (DEKs) are wrapped by one KEK.
   Missing: multiple KEKs, per-user/per-tenant KEKs, and the KEK never leaving the secure store.
4. **Wrap/unwrap**: `KeyManagementService.store_secrets/get_secrets` (AES-256-GCM, AAD = key reference) can be
   kept as the interface; replace `_get_kek` with a call into the real key service.
5. **Access control/authentication**: none today (anyone with the OS user account can read the key file).
6. **Rotation**: re-wrap all records with the new KEK (cheap); rotating a DEK needs re-encryption, which the Edit
   workflow (`VaultService.reencrypt`) already performs safely.
7. **Backup/recovery**: the app refuses to create a replacement key when wrapped records exist
   (`KeyStoreError`), but there is no escrow or recovery. Losing `DEDV_key.txt` loses every file.
8. **Revocation/deletion**: `KeyManagementService.delete` removes a record; there is no secure-delete or revocation list.
9. **Audit logging**: none.
10. **Migration**: add a migration that unwraps with the DEDV key and re-wraps under the new KEK; legacy
    `dev_keys.json` entries are migrated by re-encrypting the file (Edit page).
11. **Temporary plaintext**: prefer in-memory viewers only; for external opens use a per-user RAM-backed or
    EFS-protected location and securely delete; today files are deleted (not wiped) at app exit/next start.

Reusable as-is: `KeyManagementService` interface, `wrapped_keys.json` record format, `VaultService.reencrypt`.
Incomplete: everything in items 1, 2, 5, 7, 8, 9.

## E. Installation and data preservation

Binaries go to `<install dir>` (read-only, replaced on upgrade). User data is outside it: settings in
`%APPDATA%\DEDV`, key in `%LOCALAPPDATA%\DEDV\keys`, vault in the folder chosen at setup. `DEDV.iss` has no
`[InstallDelete]`/`[UninstallDelete]` entries, so upgrades, reinstalls and uninstalls do not touch that data.
The key file is created at runtime on first encryption and is never packaged (`build.bat` fails the build if a
key or settings file appears under `dist`).

Build (from the repository root, Python 3.13, `pip install -r requirements.txt`, Inno Setup installed):

```
.\build.bat
```

Output: `dist\DEDV\DEDV.exe` and `installer\DEDV_Setup.exe`. Quick packaged check (no UI, exit code 0 = OK; also does an
encrypt/decrypt round trip for all five levels in memory and checks the PDF viewer libraries load):

```
dist\DEDV\DEDV.exe --selftest result.json
```

To prove an existing vault is still readable (counts only, nothing is written), add its `...\DEDV` folder; the DEDV key must be
reachable (default location, or set `DEDV_KEY_DIR`):

```
dist\DEDV\DEDV.exe --selftest result.json "D:\Documents\DEDV"
```

The installer was tested as described in section C. Verify data survives an upgrade on your own install: encrypt a file, note `<vault>\metadata\files.json` and
`%LOCALAPPDATA%\DEDV\keys\DEDV_key.txt` timestamps, run the new `DEDV_Setup.exe`, start the app, double-click the file in
View. The key file's timestamp must be unchanged and the file must open.

## F. Handover checklist

* **Works** (see section C): prediction, five-level encryption, view, edit, key reuse.
* **Entry points**: `dedv/main.py`; services in `dedv/services/`; UI in `dedv/ui/`.
* **Algorithms**: `encryption/aes.py`, `chacha.py`, `rsa.py`, `mlkem.py`; mapped in `services/encryption_service.py`.
* **Add an algorithm**: add a module in `encryption/` with `encrypt_bytes/decrypt_bytes`; add an id and a name in
  `encryption_service.py`, a branch in `_encrypt` and `decrypt_bytes`; add it to `LEVEL_ALGORITHM` (and, for a new level,
  to `security_decision_service.ENTERPRISE_FINAL_LEVELS`/`PERSONAL_LEVELS`); add the module to `hiddenimports` in `DEDV.spec`;
  add a test in `tests/test_crypto.py`. Old files keep working because `algorithm` is stored per file.
* **Test**: `python -m pytest tests -q` (isolated key/temp folders; never touches real vaults or the real key).
* **Loading component**: `TaskRunner.run(fn, on_done, on_error)` shows `LoadingOverlay` (spinner + "Encrypting") before
  starting `fn` on a Qt thread-pool thread; callbacks run on the GUI thread after the overlay is hidden; only one task can run.
* **Needs more work**: key management (section D), large files, cross-process locking, accessibility of the spinner.
* **Before production**: replace the DEDV key file; threat-model the temp-file path; review the Enhanced-level model
  reliability (`CONTEXT_PROMPT.md`); sign the installer; add audit logging and backup/recovery.
