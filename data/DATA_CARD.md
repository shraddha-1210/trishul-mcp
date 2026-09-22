# Trishul Data Card (Draft — Milestone 1)

Status: DRAFT after Step 2 (dataset acquisition). Counts here are raw acquisition figures; post
dedup / normalization / split numbers are added in Step 7. Do not treat this as final.

## Environment

- Python 3.12.10 on Windows 11.
- Resolved M1 package versions: datasets 3.2.0, huggingface_hub 0.27.0, sentence-transformers 3.3.1,
  faiss-cpu 1.9.0, transformers 4.47.1, blake3 1.0.9, tqdm 4.67.1, torch 2.5.1 (CPU).
- HuggingFace auth: logged in as user `erica12` (token visible to huggingface_hub).

## Acquisition summary

| Dataset | Source | On-disk | Rows (raw) | Schema | License |
|---------|--------|---------|-----------|--------|---------|
| MCPTox | anonymous.4open.science/r/AAAI26-7C02 (arXiv:2508.14925) | 21 MB | 1348 malicious_instance records across 45 servers / 353 tool pairs | nested: servers{ server_id, tool_names, clean_system_promot, malicious_instance[ security_risk_description, wrong_data, datas, metadata, poisoned_tool ] } | UNCLEAR — anonymized review artifact, no LICENSE file, README = "# AAAI26" |
| MCPSecBench | github.com/AIS2Lab/MCPSecBench | 8.3 MB | data.json 11 rows + experiments.csv 45 rows | data.json: list[{attack, prompt, result}] | MIT |
| MCP-SafetyBench | github.com/xjzzzzzzzz/MCPSafety | 3.8 MB | 245 task-config JSON files (test) | per-task: {category, question, output_format, attack_category, mcp_server_modifications, evaluators} | BSD-3-Clause (declared in pyproject.toml) |
| OWASP MCP Top 10 | github.com/OWASP/www-project-mcp-top-10 | 178 KB | reference markdown (tab_top10.md, 2025/) | markdown reference text | CC BY-SA 4.0 |
| deepset/prompt-injections | HuggingFace | 79 KB | 662 (train 546 + test 116) | {text, label} label 0=benign / 1=injection | see HF card (verify) |
| jackhhao/jailbreak-classification | HuggingFace | 7.4 MB (incl. hf cache) | 1306 (train 1044 + test 262) | {prompt, type} type benign / jailbreak | see HF card (verify) |
| allenai/wildjailbreak | HuggingFace (gated) | DEFERRED | not yet downloaded | expected TSV vanilla/adversarial pairs | AI2 ImpACT / gated terms |

Total raw on disk (excluding wildjailbreak): ~41 MB.

## Loud flags recorded during acquisition

1. MCPTox `data_length` is 1348, not the 1,312 stated in the paper abstract and our specs. It is
   unmistakably the MCPTox corpus (45 servers, 353 tool pairs, 10 attack scopes + Other, 3 call
   templates). Exact malicious-vs-other row split to be reconciled in Step 3.
2. MCPTox `def_tool/` contains 485 `.py` tool-definition files, not 353. Reconcile in Step 3.
3. MCPTox license is unclear (anonymized AAAI26 review artifact, no LICENSE file). Recorded as
   "unclear, anonymized review artifact" per owner instruction; proceed.
4. MCPSecBench ships only 11 labeled attack rows + 45 experiment result rows in-repo, far below the
   "~1.5k examples" our specs assumed. The "17 attack types" is a taxonomy, not 1.5k rows.
5. MCP-SafetyBench is a benchmark framework (`mcpuniverse`) with 245 per-task JSON configs (each
   carrying an `attack_category`), not ~2k flat labeled text rows. Taxonomy mapping in Step 3 must
   extract from these configs, not from a flat dataset.
6. wildjailbreak: DEFERRED, not failed. Gated access not yet granted for account `erica12`.
   Owner is retrying the license grant in parallel; if it comes through during M1 the corpus is
   pulled and added. M1 proceeds without it; Step 4 synthetic augmentation carries more weight.

## Reserved sources (not in the training pipeline)

- **MCP-SafetyBench** (245 task-config JSON files) moved to `data/reserved/mcp-safetybench/`.
  Dropped from training per owner decision: the configs are scenarios, not text rows, and extracting
  them needs the framework runner (out of M1 scope) or unreliable synthesis. Reserved for M6 attack
  coverage validation. License BSD-3-Clause.
- **OWASP MCP Top 10** is reference-only: used to validate taxonomy coverage, contributes zero
  training rows. License CC BY-SA 4.0.

## Taxonomy mapping (source label -> Trishul class)

Canonical taxonomy = the 18 classes in implementation.md §4.2 plus `benign`.

| Source | Source label | Trishul class | Rationale |
|--------|--------------|---------------|-----------|
| MCPTox | ALL 1348 (any `security risk`) | tool_description_poisoning | Owner decision Option A: every MCPTox instance is a tool-metadata poisoning attack by vector; `security risk` kept as `impact_category`, `paradigm` as `attack_template` |
| MCPSecBench | Tool Poisoning Attack | tool_description_poisoning | direct match |
| MCPSecBench | Data Exfiltration | data_exfiltration | direct match |
| MCPSecBench | Rug Pull | rugpull_redefinition | direct match |
| MCPSecBench | Indirect Prompt Injection | indirect_prompt_injection | direct match |
| deepset | label 1 | indirect_prompt_injection | injection corpus (note: deepset is mostly *direct* injection; nearest Trishul class) |
| deepset | label 0 | benign | benign |
| jackhhao | jailbreak | jailbreak_payload | direct match |
| jackhhao | benign | benign | benign |

## Held (STOP-and-ask, not dropped, not bucketed)

MCPSecBench categories with no confirmed mapping, 1 row each (7 total): Tool Shadowing Attack,
Package Name Squatting (Server Name), Package Name Squatting (Tool Name), Prompt Injection (direct),
Sandbox Escape, Tool Misuse via Confused AI, Vulnerable Server. Awaiting owner ruling before they
enter (or are dropped from) the corpus. Since each is a single row, adding them later only affects
`train_real.jsonl`, never the frozen val/test.

## Preprocessing config

- Seed: 42 (stratified split).
- Canonicalization: `training/canonicalize.py`, implements Layer 1.5 exactly (impl §3.2): NFKC, strip
  U+200B-200F / U+FEFF / U+E0000-E007F / U+202A-202E / U+2066-2069, base64 decode+recurse (depth 3).
  M2's Layer 1.5 worker must reuse this module.
- Dedup: BLAKE3 (16 hex) of canonical text, global first-wins.

## Per-source counts (Step 3, post canonicalization)

| Source | Pre-dedup | Dups | Post-dedup | Dedup % |
|--------|-----------|------|-----------|---------|
| mcptox | 1348 | 10 | 1338 | 0.7% |
| mcpsecbench | 4 (mapped) | 0 | 4 | 0.0% |
| deepset | 662 | 0 | 662 | 0.0% |
| jackhhao | 1306 | 17 | 1289 | 1.3% |

No source exceeded the 30% dedup STOP threshold.

## Per-class real-data counts (pre-augmentation)

| Trishul class | Real rows | Note |
|---------------|-----------|------|
| tool_description_poisoning | 1339 | ok |
| benign | 1037 | ok |
| jailbreak_payload | 651 | ok |
| indirect_prompt_injection | 264 | <500, synthetic to 1500 (10x reaches it) |
| data_exfiltration | 1 | cannot reach 1500 floor via paraphrase -> STOP |
| rugpull_redefinition | 1 | cannot reach 1500 floor via paraphrase -> STOP |
| secret_credential_leak | 0 | path-b class, no seed -> STOP |
| command_code_injection | 0 | path-b class, no seed -> STOP |
| pii_harvesting | 0 | path-b class, no seed -> STOP |
| schema_drift | 0 | path-b class, no seed -> STOP |
| confused_deputy_exfil | 0 | path-b class, no seed -> STOP |
| unicode_tag_smuggling | 0 | deterministic path (a), fine |
| zero_width_obfuscation | 0 | deterministic path (a), fine |
| homoglyph_substitution | 0 | deterministic path (a), fine |
| ocr_image_injection | 0 | deterministic path (a), fine |
| audio_injection | 0 | deterministic path (a), fine |
| phishing_url_injection | 0 | deterministic path (a), fine |
| denial_of_wallet | 0 | deterministic path (a), fine |
| cross_call_split_payload | 0 | deterministic path (a), fine |

Splits: train_real 2639, val 327, test 327 (val/test real-only, frozen).

## Class training strategy (owner Decision B, Option A)

The 19 classes split into two disjoint groups by *which layer detects them*, not by outcome.

**ML-trained text classes (12) -> `data/processed/train.jsonl`.** These are text-distinguishable
*after* Layer 1.5 canonicalization, so the Layer 4 ML classifier (DeBERTa, impl §4.5) can learn
them: `phishing_url_injection` (URL survives canonicalization), `indirect_prompt_injection`,
`jailbreak_payload`, `secret_credential_leak`, `command_code_injection`, `data_exfiltration`,
`pii_harvesting`, `rugpull_redefinition`, `tool_description_poisoning`, `schema_drift`,
`confused_deputy_exfil`, `benign`. Synthetic augmentation targets the 1,500 floor for the sparse
ones and is appended only to `train.jsonl`; `val.jsonl`/`test.jsonl` stay real-only and frozen.

**Deterministic ARTIFACT-only classes (7) -> `data/synth/<class>/`, never in the ML corpus.**
`unicode_tag_smuggling`, `zero_width_obfuscation`, `homoglyph_substitution` (Layer 1.5),
`ocr_image_injection`, `audio_injection` (Layer 1), `denial_of_wallet` (Layer 6),
`cross_call_split_payload` (Layer 3). Reason: after Layer 1.5 canonicalization their `text` is
byte-identical to a plain injection (measured: tag-smuggling 178->65 chars, zero-width 375->221
chars once the invisible payload is stripped). Feeding those canonicalized rows to the ML
classifier would teach it to map ordinary post-canon injection text to a delivery-mechanism label,
i.e. inject false-positive signal on legitimate injections. These classes are detected
deterministically upstream, so they are emitted as fixtures for M2 unit tests + M6 attack staging.

## Artifact generation (Step 4a, deterministic path)

`training/generate_artifacts.py`, seed=42. Base payloads sampled from the 204 real
`indirect_prompt_injection` texts in `train_real.jsonl` (length 12..600) so the transforms
obfuscate real attack text rather than invented strings. `denial_of_wallet` is the one exception:
a rate pattern with no text signal, emitted as structured call-burst templates (inherently
synthetic, flagged). Each manifest row stores both the obfuscated form and its post-`canonicalize.py`
form. Counts are FIXTURE counts (adjustable), not the 1,500 ML floor.

| Artifact class | Detector | Rows | Media files |
|----------------|----------|------|-------------|
| unicode_tag_smuggling | Layer 1.5 | 150 | - |
| zero_width_obfuscation | Layer 1.5 | 150 | - |
| homoglyph_substitution | Layer 1.5 | 150 | - |
| cross_call_split_payload | Layer 3 | 100 | - |
| denial_of_wallet | Layer 6 | 60 | - |
| ocr_image_injection | Layer 1 (OCR) | 80 | 80 PNG |
| audio_injection | Layer 1 (STT) | 40 | 40 WAV |

Total: 730 manifest rows + 120 media files under `data/synth/`.

Loud findings from Step 4a:
1. **Homoglyph vs NFKC:** `canonicalize.py` (impl §3.2) does NOT fold homoglyphs (measured:
   homoglyph artifact 92->92 chars, unchanged). NFKC leaves Cyrillic/Greek lookalikes intact. A
   dedicated homoglyph detector is required in the M2 Layer 1.5 worker; canonicalization alone will
   miss this class. Recorded in each homoglyph manifest row.
2. **pyttsx3 background stall:** a single long-lived SAPI5 engine deadlocks in `runAndWait()` when
   looped inside a detached/non-interactive shell (stalled at 2/40 WAVs). Fixed by re-initializing
   the engine per file and running audio generation in the foreground. All 40 WAVs verified valid.

## Loud finding: Llama paraphrase quality probe (Step 4b) FAILED the class-fidelity check

Probe: `generate_synthetic.py --class indirect_prompt_injection --validate 20` (212 real seeds,
llama3.1:8b). Mechanical rejection rate was 0% (length/dedup/coherence all passed), BUT the 20 kept
examples are semantically BENIGN roleplay / Q&A, not indirect prompt injections (e.g. "what is the
significance of the color blue in art history?", "Imagine you're a time traveler from ancient
Egypt"). Root causes: (a) the `indirect_prompt_injection` seeds come from deepset label=1, which are
mostly user-side / roleplay prompts, weak as attack exemplars; (b) the generation prompt asks for a
"tool RESPONSE body containing the attack" while the seeds are user prompts -> framing mismatch;
(c) `accept()` only filters length/dedup/coherence, so off-class benign text passes. STOPPED before
any path-b mass generation per the "any quality issue -> STOP" rule. Awaiting owner decision on the
generation fix (stronger prompt + class-validation filter + hand-written attack seeds).

## Pending decisions before Step 4

1. Ruling on the 7 held MCPSecBench categories above.
2. How to seed the 7 sparse path-b classes that cannot reach the 1,500 floor (see report).
3. Confirm class-name canonicalization: this pipeline uses impl §4.2 names (ocr_image_injection,
   audio_injection, denial_of_wallet, rugpull_redefinition); decision-2 used variant names
   (ocr_embedded_instruction, audio_embedded_instruction, denial_of_wallet_flood,
   rug_pull_redefinition).
