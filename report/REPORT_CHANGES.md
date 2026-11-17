# Changes from `DEDV_2.tex` to `DEDV_2_revised.tex`

## Files

| File | What it is |
|---|---|
| `DEDV_2_original.pdf` | The paper as received (`DEDV (2).pdf`). |
| `DEDV_2.tex`, `DEDV_2.bib` | Faithful transcription of that PDF, errors included. No `.tex` source existed, so it was rebuilt from the PDF text. Figs. 1–2 are redrawn in TikZ; Fig. 3 is drawn from the counts printed in the PDF. Before its first commit only the redrawn figures were adjusted (a TikZ style name that stopped compilation, the missing colour-map library, and box sizes, colours and arrow routing to match the PDF); the text was not changed. **Frozen from its first commit on.** |
| `DEDV_2_revised.tex`, `DEDV_2_revised.bib` | The revised paper. |
| `DEDV_2_diff.tex` | `latexdiff-so --encoding=utf8 --config="PICTUREENV=(?:picture|DIFnomarkup|tikzpicture|tabular)[\w\d*@]*" DEDV_2.tex DEDV_2_revised.tex` (MiKTeX's script run with Git for Windows' Perl). Tables and TikZ figures are marked as whole blocks, because markup inside them breaks compilation. latexdiff does not mark changes inside `\abstract{…}`; the abstract changes are listed below. |
| `DEDV_2.pdf`, `DEDV_2_revised.pdf`, `DEDV_2_diff.pdf` | Compiled versions (19, 24 and 28 pages). |
| `sn-jnl.cls`, `sn-mathphys-num.bst` | Springer Nature LaTeX template, December 2024 version, from the official package on springernature.com. |

Build either paper from `report/`: `pdflatex X`, `bibtex X`, `pdflatex X`, `pdflatex X`.
The revised paper includes the benchmark figures from `../bench/results/`.

Section, table and figure numbers below are those of the **revised** paper unless marked "orig.". The
revised paper adds Section 6 (System Implementation), so orig. Sections 6–10 are now 7–11. New
tables and figures shift the numbering: orig. Tables 2–3 are now Tables 3–4 (the new mapping table is
Table 2), and orig. Fig. 3 is now Fig. 6.

## Problems that were asked to be fixed

| # | Where | Change | Reason / evidence |
|---|---|---|---|
| 1 | Sec. 8 (orig. 7), Sec. 8.1 (orig. 7.1) | "…with 72.5" now reads "…and an accuracy of 72.5\%."; "…close to 15.9" now reads "…is 15.9\%, compared with 13.0\% for the ten-input model". Checked the whole file: every `%` in the text is now `\%`. | An unescaped `%` turned the rest of each line into a comment. The lost words are unknown, so the sentences were rewritten from the verified values (72.5 %, 15.9 %, 13.0 % in `CONTEXT_PROMPT.md` §5). |
| 2 | Abstract | 10-input RF macro-F1 0.398 → **0.389 ± 0.026**. | `CONTEXT_PROMPT.md` ("macro-F1 0.389 +/- 0.026 on all 10 inputs"); orig. Tables 2–3 (now Tables 3–4), Sec. 8.1 and the Conclusion already said 0.389. |
| 3 | Sec. 9 (orig. 8) | "seven records" → removed; the count is **eight** everywhere (abstract, Sec. 9). | `CONTEXT_PROMPT.md`: "Clean class counts: … Enhanced 8 … from 8 different respondents". |
| 4 | Fig. 6 (orig. Fig. 3), Sec. 9 | The figure is kept but relabelled honestly: title "Survey-target experiment (not the selected K7 model)", row totals on the axis (20 / 71 / 178 / 133), and a caption that says it is a Random Forest trained on the respondents' survey answer (178 Enhanced records), not the K7 model. The Limitations text says the K7 matrix is not available. `% VERIFY` comment left. | The rows sum to 178 Enhanced records (the K7 target has 8), implied accuracy ≈ 47.5 % (K7: 72.5 %), Enhanced P/R ≈ 0.54/0.46 (K7: ≈ 0.10). `CONTEXT_PROMPT.md` confirms the survey-answer labelling has 178 Enhanced rows. No K7 matrix exists in the repository or `CONTEXT_PROMPT.md`, so none was invented. |
| 5 | Sec. 5.1, Sec. 1 (parameter paragraph) | Sec. 5.1 now separates (a) the ~12 factors from the literature that guided the survey, (b) the 10 survey inputs (7 per-scenario answers + Respondent Type, Scenario, Digital Document Handling Frequency) and (c) the 7 inputs of the final K7 model. States that file type, size and content are not model inputs because the model never inspects the file. Added how inputs are encoded. Sec. 1 points to 5.1 instead of implying all 12 are used. Sec. 3.2: "Multiple Locations" → "Multiple Locations/Countries" (the exact input name). | `CONTEXT_PROMPT.md` §3 (10 inputs) and §5 (K7 inputs, and why the 3 respondent attributes were dropped); `dedv/services/security_decision_service.py` docstring ("It never inspects the file"). |
| 6 | Sec. 5.4 | First sentence reversed: "The encryption configuration is selected from the security level assigned to the document." Removed the retrieval sentences that did not belong to this subsection, added that one mapping serves both vaults and that the service layer re-checks it. | Causality was backwards; `encryption_service.LEVEL_ALGORITHM`, `vault_service._store_one`. |
| 7 | Sec. 1, 2.7, 3.1, 3.2, 9 and throughout | Removed the stray bullet "DEDV deals with all the following mentioned points."; Sec. 2.7 no longer opens with a dangling "Instead," ("The proposed work therefore focuses…"); removed the duplicated "Random Forest is used as a decision engine" in 3.1; "another configuration" → "another challenge" in 3.2; Limitations restructured as First/Second/Third (the orig. had "Second" with no "First"). Typos: delt → dealt/applied, deatection → detection, encrypiton → encryption (sentence rewritten), clous → cloud, hondle → handle, reequipments → requirements, documenta → documents, Rando → Random, acro F1 / F1 core → macro-F1. | Text cleanup requested. |
| 8 | Bibliography | [3] Smallwood: added `address = {Hoboken, NJ}` (the "???" came from the missing address). [10]: authors "Sagar, S. and Keke, C." → **"Sharma, S. and Chen, K."**, DOI added; the text in Sec. 2.5 now says "Sharma and Chen" instead of "Sagar and Chen". | Verified online: the survey (Cybersecurity 4, 30, 2021, doi:10.1186/s42400-021-00092-8) is by Sagar **Sharma** and Keke Chen (DOAJ, arXiv 2012.08156, PMC8591683), so "Sagar" is the first author's given name. Smallwood's book: John Wiley & Sons, Hoboken, New Jersey, 2012 (publisher and library records). |
| 9 | Sec. 4, 5.5, 5.6, 7.4 (orig. 6.4) | Key management and retrieval now describe the implementation: per-file random key; record sealed with AES-256-GCM under the VMK in `keys.db`, found by a random 128-bit token; AAD = token ‖ file id ‖ algorithm ‖ level; `vault.db` stores only the token; `release_key` refuses when locked, for an unknown token or a token of another file, and audits every call; decryption in memory. | `key_management_service.py`, `vault_service.py`, `auth_service.py`. |

## Additions that were asked for

| Where | Addition | Source |
|---|---|---|
| Sec. 6 (new) "System Implementation" | Architecture (UI → services → crypto/storage), vault folder layout and the two databases, level → encryption mapping, key hierarchy (password → Argon2id → KEK → VMK → per-file key record, token-indexed, AAD binding), recovery key, authorization and `release_key`, failed-unlock delays, auto-lock, audit log (and its limit: unkeyed), decision flow and upward-only override, what is stored per file, migration from 0.1, technology stack. | The code on branch `finish-build`; versions from `bench/results/environment.json`. |
| Fig. 1 | Redrawn to match what is built: 7 named inputs → RF (K7) with confidence → vault rules (incl. upward-only override and acknowledgement) → encryption → ciphertext file / sealed key record in `keys.db` → retrieval through `release_key` with audit. Caption: "System model of DEDV as implemented." | Same. |
| Fig. 3 (new) | (a) architecture layers, (b) key hierarchy. | Same. |
| Table 2 (new) | Level → algorithm for both vaults, with the key material stored per file. Notes that the RSA/ML-KEM private key sits in the same sealed record, so the asymmetric step adds no protection beyond the VMK seal, and that Critical is not claimed to be quantum-resistant. | `encryption_service.LEVEL_ALGORITHM`, `encryption/*.py`. |
| Sec. 7.5, Sec. 8.3, Figs. 4–5, Table 5 (new) | Benchmark method and results. | `bench/benchmark.py`, `bench/results/summary.csv`. |
| Sec. 9 Limitations | Added: single user, no hardware-backed key storage, best-effort memory zeroing and temp-file wipe, unkeyed audit chain, whole files in memory, installer not code-signed. ML limitations kept and tightened (15.9 % vs the 16.0 % limit). | Code and `build.bat` (no signing step). |
| Sec. 10 Future Scope | No longer promises encryption timing (now measured); lists the open items instead. | — |
| Sec. 11 Conclusion | Summarises the implementation and the measured costs. | — |
| Bibliography | Added RFC 9106 (Argon2), FIPS 203 (ML-KEM), NIST SP 800-38D (GCM), RFC 8439 (ChaCha20-Poly1305), RFC 8017 (RSA-OAEP), RFC 5869 (HKDF), cited in Sec. 6. [14]: journal "IEEE Security Privacy" → "IEEE Security \& Privacy". | Standard documents. |

## Other changes

| Where | Change | Reason |
|---|---|---|
| Abstract | Rewritten in plainer English; "67 responses" → "67 respondents"; adds the implementation and the benchmark result in one sentence each. | Clarity; `CONTEXT_PROMPT.md` (67 respondents × 6 scenarios = 402 records). |
| Sec. 1 | Organization paragraph updated for the new Section 6. One contribution bullet added (prototype and measurements). Small grammar fixes ("The border relevance" → "The broader relevance", "for a documents" → "for a document", etc.). | Structure; clarity. |
| Sec. 4 | Explains what happens to a High/Critical prediction in each vault (Enterprise: choose High or Critical; Personal: no level, use an Enterprise vault) and that the model reports a confidence. | `security_decision_service.py`. |
| Sec. 5.2, 5.3 | Model descriptions reworded; 5.3 states that the vault type restricts the final levels but does not change the prediction. | Clarity; code. |
| Sec. 7.1 (orig. 6.1) | States the validation protocol (402 originals, respondent-grouped stratified 5-fold CV, 5 seeds, mean ± std over repeats). | `CONTEXT_PROMPT.md` §4. |
| Sec. 8.1 | Adds the majority-class baseline (75.4 % accuracy, macro-F1 0.215) to explain why accuracy is not used for selection, and states the predefined selection criteria (macro-F1 ≥ 0.364; High/Critical → Low/Standard ≤ 16.0 %). Rewrote the contradictory last sentence of the orig. trade-off paragraph. | `CONTEXT_PROMPT.md` §4–5. |
| Sec. 8.2 | Adds how the implementation reacts to uncertain predictions (confidence shown, acknowledgement, upward-only override). | Code. |

## `% VERIFY` items left in `DEDV_2_revised.tex`

1. **Table 3** (orig. Table 2): the KNN row (0.320 ± 0.019, 75.0 ± 0.6), the ± values of DT, XGB and MLR, and all
   accuracy values. `CONTEXT_PROMPT.md` confirms only the macro-F1 means of MLR (0.345), XGB
   (0.334), DT (0.324) and the 10-input RF (0.389 ± 0.026). Values are kept as in the original.
2. **Table 4** (orig. Table 3): the 10-input RF accuracy (75.4 ± 0.8) and the ± 1.6 of the 7-input accuracy.
   72.5 % itself is confirmed.
3. **Fig. 6** (orig. Fig. 3): relabelled, not replaced. Replace it with the K7 confusion matrix if
   that becomes available (the training data are on another PC).

Nothing else in the revised paper is a number that was not checked against `CONTEXT_PROMPT.md`,
the code, or `bench/results/`.
