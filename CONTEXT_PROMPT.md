# Context prompt: DEDV security-level model, PCA and web test page

You are continuing work on the user's **Dynamic Encryption Digital Vault (DEDV)** project. Read this fully before touching anything. Do not re-derive what is already established, and do not claim more than the numbers support.

## 1. Task and boundaries
- Goal: predict the document **security level** (4 classes, fixed order `Low, Standard, Enhanced, High/Critical`) from survey-style inputs. The model predicts the level only, never the encryption method.
- Do NOT modify encryption algorithms, key management, tokenization or decryption/authorization logic. Do not modify `SecureVault_ML/` (Desktop; its `src/predict.py` uses a different 9-feature schema and a 0.70 confidence rule, `REVIEW_REQUIRED` below it).
- Project root: `C:\Users\Lenovo\OneDrive\Desktop\My own data training` (Windows, Git Bash and PowerShell available; Python 3.13, scikit-learn 1.6.1, xgboost 3.4.1, pandas 2.2.3, node 22, Chrome installed). Not a git repo.
- Never read or touch `C:\Users\Lenovo\Downloads\Chrome Passwords.csv`.

## 2. The data (verified)
- Source files (copied to `data/source/`): `organizational_clean.csv` (402 original rows = 67 respondents x 6 scenarios), `organizational_augmented.csv` (574), `organizational_balanced.csv` (400), the survey export (has `User ID`) and `SecureVault_PERSONAL_AND_ORGANIZATIONAL.xlsx` (documents the 6-level scheme and derived labels).
- Clean class counts: Low 20, Standard 71, **Enhanced 8**, High/Critical 303. The 8 Enhanced rows come from 8 different respondents.
- **Augmented/balanced add no information:** every synthetic row is an exact duplicate of an original row. Never score or train on them; they cause leakage and false confidence. Only the 402 originals are used.
- `User ID` is not a column in the CSVs. It was recovered by matching each survey respondent to one block of six consecutive rows; it is identical to the team's timestamp grouping (verified). Code: `dedv_ml/source_data.py` (`load_clean()` adds `user_id`, `row_id`, `survey_label`, `derived_level`, `source_level`, `feature_score`, `timestamp`; these are metadata for grouping/diagnostics, NEVER model inputs).
- **Why Enhanced fails (key finding):** the clean file's "Enhanced" is workbook derived Level 3 ("Moderate" in the workbook's own table). Rule, reproduced on all 402 rows: survey answer Enhanced and feature score <= 6 -> Level 3 (the 8 rows), else Level 4; survey High/Critical and score <= 8 -> Level 5, else Level 6. The team maps L3 -> "Enhanced", L4/5/6 -> "High/Critical". The survey itself had 178 Enhanced answers. The label depends on a survey answer that is not an input, so inputs cannot determine it. Details: `results_enhanced/enhanced_class_diagnostic.md`.
- The earlier confusion matrix with 402 observations (20/71/8/303) was the team's original-records-only validation, not a dataset mix-up.

## 3. Inputs (10 columns, exact strings from the CSV; keep the source typo)
Ordinal (explicit order, low -> high):
- `Digital Document Handling Frequency`: Rarely, **Occasionaly** (sic), Frequently, Very frequently
- `Sensitivity`: Low, Moderate, High, Very High
- `Access Frequency`: Rarely, Occasionally, Monthly, Weekly, Daily
- `Exposure Consequence`: Very Low, Low, Moderate, High, Very High
- `Protection Duration`: Less than 1 year, 1–5 years, 5–10 years, More than 10 years, Permanently (en dashes)

Nominal (one-hot, unknown categories ignored): `Respondent Type`, `Scenario` (integer 1-6, treated as a label, cast to string), `Who Should Access`, `Multiple Devices`, `Multiple Locations/Countries`.

Preprocessing (`dedv_ml/pipeline.py: build_preprocessor(features=None)`): ordinal -> `OrdinalEncoder` (given categories, unknown -> NaN) -> median impute -> `StandardScaler`; nominal -> cast to str -> `OneHotEncoder(handle_unknown="ignore")`. Encoded width for all 10 inputs = 28 columns (5 ordinal + 23 one-hot). Always fitted inside the `Pipeline`, so only on training rows.

## 4. Validation protocol (use it for any new experiment)
- Only the 402 originals are scored. `StratifiedGroupKFold(5, shuffle=True)` with groups = `user_id`, **5 repeats with seeds 42-46**, identical folds for every experiment (`dedv_ml/experiments.py: make_repeated_folds`). Asserts zero respondent overlap.
- Metrics are pooled out-of-fold per repeat, then mean +/- std over repeats (std = split noise, NOT sampling uncertainty; bootstrap over the 8 Enhanced records gives the honest range, e.g. recall 0.00-0.30).
- Always report macro-F1 (primary), Enhanced precision/recall, and **High/Critical predicted lower** (especially High/Critical -> Low/Standard). Never select on accuracy (majority baseline already scores 0.754 accuracy, macro-F1 0.215; stratified random 0.245).
- Hyper-parameters are fixed a priori, not tuned (8 positives would fit noise). No SMOTE (all inputs categorical). Resampling or class weights only inside training folds.

## 5. Model plan and parameters
**Selected plan (earlier experiment "C"):** `RandomForestClassifier(n_estimators=300, max_depth=6, min_samples_leaf=3, class_weight="balanced_subsample", random_state=42, n_jobs=1)` (`experiments._rf()`), macro-F1 0.389 +/- 0.026 on all 10 inputs. Other earlier results (macro-F1): LogReg baseline 0.345, LogReg balanced 0.330, XGBoost weighted 0.334, DecisionTree balanced 0.324, RF+oversample 0.305, LogReg+oversample 0.339. Top models differ by about the noise.

**Enhanced is not reliable in any experiment** (best precision 0.21, best recall 0.33, never both; the apparent hits are mostly one record, row 182).

## 6. PCA findings
- PCA is fitted inside each pipeline (`PCA(n_components=<variance fraction>, svd_solver="full", random_state=42)`) after the encoder. On all 10 inputs: 11 / 15 / 18 components for 80 / 90 / 95% variance; largest component 23.7%; variance is spread evenly because inputs are categorical.
- **PCA hurt in every validated variant:** all-10 PCA(80/90/95) macro-F1 0.349 / 0.334 / 0.341; core-7 PCA(80/90/95) 0.337 / 0.345 / 0.341, versus 0.389 (all-10) and 0.380 (core-7) without PCA. Enhanced recall fell to ~0.
- PCA is unsupervised and cannot say which inputs predict the label. An attempt to rank inputs by PCA loadings was an artefact (standardised ordinal columns have more variance than one-hot flags, so it just listed the five ordinals first); it was discarded and kept in `abandoned_pca_ranked_subsets.csv`. Do not reuse that ranking.
- Descriptive PCA of the 7 final inputs: 9 components reach 90%; PC1 (32%) loads on Sensitivity, Exposure Consequence, Protection Duration; PC2 (17.5%) on Access Frequency; PC3 (10%) on Protection Duration. See `pca_loadings_final_inputs.csv`.

## 7. Which inputs are needed
- Selection rule (fixed before the runs): reference = RF on all 10. "Adequate" = macro-F1 >= reference - 1 std (0.364) AND High/Critical -> Low/Standard <= reference (0.130) + 0.03 = 0.160. PCA configurations preferred; then fewest inputs; then fewest components. No PCA configuration was adequate, so the fallback applied.
- **Selected: "K7" = RF, no PCA, 7 per-scenario survey answers:** `Sensitivity, Who Should Access, Access Frequency, Exposure Consequence, Protection Duration, Multiple Devices, Multiple Locations/Countries`. Not needed: `Respondent Type, Scenario, Digital Document Handling Frequency` (they describe the survey taker, not the document).
- Validated: macro-F1 0.380 +/- 0.024, accuracy 0.725, Enhanced P 0.10 / R 0.10, High/Critical -> Low/Standard 15.9% (passes the 0.160 limit by only 0.001; the all-10 model is safer at 13.0%).
- Leave-one-input-out (macro-F1 change vs 0.389): Who Should Access -0.037, Sensitivity -0.036, Access Frequency -0.022, Protection Duration -0.021, Multiple Devices -0.018, Scenario -0.010, Respondent Type -0.009, Exposure Consequence -0.004, Locations +0.001, Handling Frequency +0.004. Differences below ~0.026 are noise.
- Selection was done on the same small data after comparing several configurations, so the K7 score is slightly optimistic. Changing the selection rule after seeing results is cherry-picking; say so if you must.

## 8. Files (`Final_Modal_and_test/`)
`build_final_model.py` (whole pipeline: validate configs, select, refit on 402 rows, export, report; ~10 min), `final_model.joblib` (sklearn Pipeline), `model.js` (exported model: ordinal means/scales, one-hot categories, optional PCA, 300 trees as flat arrays, validation numbers, 4 examples), `index.html` + `style.css` + `app.js` (page), `parity_check.js` + `parity_cases.json` (JS vs sklearn: 702 cases, max diff 4.7e-8, 0 label mismatches), `config_comparison.csv`, `pca_*.csv`/`pca_overview.png`, `Final_Model_Report.md`, `model_summary.json`, `page_screenshot.png`, `abandoned_pca_ranked_subsets.csv`.
Other relevant code: `dedv_ml/` (config, data, pipeline, validation, evaluation, plotting, source_data, diagnostics, experiments, enhanced_report), `diagnose_enhanced.py`, `run_enhanced_experiments.py`, `train_models.py` (first-task pipeline, `results/`), `predict_security_level.py` (loads `results/best_model.joblib`, unchanged). Results: `results/` (first task), `results_enhanced/` (diagnostic + 14 experiments).

## 9. Web page facts
- Opens from disk (`model.js` is a script tag, no fetch). Form is built from `model.js`; JS pipeline = encode -> standardise -> (PCA if present) -> average leaf probabilities of 300 trees, comparing `Math.fround(x) <= threshold` like sklearn's float32. Tree class order in the export is alphabetical (`Enhanced, High/Critical, Low, Standard`); the page maps it to the display order.
- Confidence < 0.70 shows REVIEW REQUIRED. Predicting Enhanced always shows a warning with the validated Enhanced precision/recall. The PCA panel is hidden when the model has no PCA. Examples are training rows ("seen by model"), so they do not demonstrate generalisation. `?example=N` auto-loads an example (handy for headless tests).
- Re-export after retraining: run `build_final_model.py`, then `node parity_check.js` inside the folder; it must print 0 mismatches.

## 10. Working notes and pitfalls
- In Bash heredocs, backslash sequences like `\n` inside Python source passed through the tool get altered, which broke several `str.replace` patches. Use the Edit tool for edits containing backslashes, or write files with Write.
- Use the Artifact-free approach; outputs are local files. Chrome headless screenshots need Windows paths via PowerShell.
- Do not fabricate metrics; report failures plainly. Do not call any model production-ready. Do not relabel data automatically.

## 11. Recommended next steps (not done)
1. User must decide what "Enhanced" means (survey answer, 178 rows / workbook Level 5, 17 rows / Level 3, 8 rows), rename classes to the workbook's names, and retrain with the same validation.
2. Manual review of the 8 Enhanced rows and `results_enhanced/potential_label_conflicts.csv` (3 pairs are one respondent giving identical answers different levels).
3. Collect Enhanced examples from many more respondents and add the inputs the workbook says define Enhanced (number/role of authorized users, auditing/compliance needs, data type).
4. Until then keep low-confidence predictions as manual review and consider a rule that prevents a level below what the sensitivity input implies (suggestion only, untested).
