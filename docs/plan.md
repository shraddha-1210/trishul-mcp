# Trishul Build Plan

This document orchestrates the build. It does not restate specifications. What to build is in
`implementation.md` (referenced as impl §N); how to prove it is in `testing.md` (referenced as test
§N). Section map:

- §1 Overview
- §2 Rules of Engagement
- §3 Milestones (M1 through M8)
- §4 Data Sourcing Plan
- §5 Attack Reenactment Plan
- §6 Risk Register
- §7 Out of Scope
- §8 Open Questions

---

## §1 Overview

Trishul is built bottom-up: first the data that every model depends on, then the detection layers from
cheapest to most expensive, then enforcement, then the attack suite that proves it, and finally the UI
and demo. Each milestone builds a defined set of implementation.md sections and is considered done only
when the corresponding testing.md assertions pass. All models and tools are free and local, and no git
or GitHub operation is performed at any point.

---

## §2 Rules of Engagement

- No git write operations, ever. Read-only git inspection is allowed; commit, push, add, branch, tag,
  and any `gh` write are not.
- No implementation code is written until a milestone is explicitly approved.
- Every milestone ends with STOP and waits for approval.
- If a spec is ambiguous or missing, flag it in §8 Open Questions instead of guessing.
- If a test fails and the fix is not in the spec, STOP and ask rather than inventing behavior.
- Every deliverable is local-only until the owner says "push it."

---

## §3 Milestones

### M1 — Data Pipeline
- **Goal:** Produce clean, split, indexed datasets and a trained-data foundation for later layers.
- **Builds (impl refs):** §2.1, §4.1, §4.2, §4.3, §4.4.
- **Tests (test refs):** test §6.1 harness scaffold and test §6.3 clean-traffic hold-out are created
  here; data-shape checks accompany the pipeline scripts.
- **Deliverables:** `data/download.py`, `data/preprocess.py`, `data/synth_generate.py`,
  `data/build_index.py`, `data/DATA_CARD.md`, `data/processed/{train,val,test}.jsonl`,
  `data/processed/faiss.index`, `data/processed/faiss_meta.jsonl`.
- **Success criteria:** downloads succeed or gaps are recorded; splits are seeded and reproducible; the
  FAISS index loads and returns sensible neighbors for known injection strings; DATA_CARD.md carries
  real counts and licenses.
- **Complexity:** L
- **Dependencies:** none.
- **Risks:** gated wildjailbreak (§6 R1); MCPTox artifact URL unconfirmed (§6 R2, §8 Q1).
- **STOP — awaiting approval before M2**

### M2 — Core Detection Layers (1, 1.5, 2a, 2b)
- **Goal:** Build the media, normalization, pattern, and semantic layers with the OCP rule interface.
- **Builds (impl refs):** §2.2, §3.1, §3.2, §3.3, §3.4.
- **Tests (test refs):** §3.1, §3.2, §3.3, §3.4.
- **Deliverables:** `workers/layer1_extraction/`, `workers/layer1_5_normalize/`,
  `workers/layer2a_patterns/`, `workers/layer2b_semantic/`, plus their `config/*.yaml` and unit tests.
- **Success criteria:** all test §3.1 to §3.4 positive, negative, boundary, failure, and latency
  assertions pass; Layer 1.5 recovers hidden instructions from the tag-block, zero-width, and homoglyph
  fixtures; Layer 2b honors the 0.70/0.85 bands.
- **Complexity:** M
- **Dependencies:** M1 (FAISS index, signature corpus).
- **Risks:** OCR/STT model footprint; threshold tuning affecting false positives (§6 R6).
- **STOP — awaiting approval before M3**

### M3 — Judge Panel and Consensus
- **Goal:** Stand up judges A to D and the consensus and degraded-lane logic.
- **Builds (impl refs):** §3.6, §4.5.
- **Tests (test refs):** §3.6, integration §5.2.
- **Deliverables:** `workers/layer4_judges/` (ollama_client, deberta, regex_judge, consensus, prompts,
  service), the fine-tuned model under `workers/layer4_judges/models/`, `config/layer4.yaml`.
- **Success criteria:** DeBERTa trains to a documented val macro-F1; consensus resolves splits
  deterministically; the panel beats any single judge on the held-out set; degraded lane behaves per
  test §5.2.
- **Complexity:** L
- **Dependencies:** M1 (training data), M2 (canonical input path).
- **Risks:** judge latency budget (§6 R3); DeBERTa CPU training underperformance (§6 R4).
- **STOP — awaiting approval before M4**

### M4 — Supporting Layers (3, 5, 6)
- **Goal:** Add cross-call aggregation, schema-drift, and rate-anomaly detection.
- **Builds (impl refs):** §3.5, §3.7, §3.8.
- **Tests (test refs):** §3.5, §3.7, §3.8.
- **Deliverables:** `workers/layer3_aggregator/`, `workers/layer5_schema/`, `workers/layer6_anomaly/`,
  their configs and unit tests.
- **Success criteria:** Layer 3 reassembles a payload split across three responses; Layer 5 flags a
  changed description while ignoring cosmetic changes; Layer 6 holds escalations past the cap without
  firing on normal bursts.
- **Complexity:** M
- **Dependencies:** M2 (2a/2b reuse in Layer 3), M3 (verdict schema).
- **Risks:** session-store scoping under concurrency (validated later in test §5.3).
- **STOP — awaiting approval before M5**

### M5 — Enforcement (Rust core, policy, capability, audit)
- **Goal:** Make verdicts binding and tamper-evident, and bound blast radius with scoped tokens.
- **Builds (impl refs):** §2.3, §2.4, §3.0, §3.9, §3.10, §3.11.
- **Tests (test refs):** §3.0, §3.9, §3.10, §3.11, integration §5.1, §5.4, §5.5.
- **Deliverables:** `core/` (Rust reference monitor + proto + mTLS), `policy/` (engine, policies,
  signer, capability, scopes), `audit/` (chain, store, verify, service), their configs.
- **Success criteria:** a BLOCK cannot be bypassed; tokens expire at 30 s and reject cross-invocation
  reuse; the audit chain detects tampering at the exact position; the fail-closed default holds under
  worker outage.
- **Complexity:** L
- **Dependencies:** M2, M3, M4 (all layers feed the policy engine).
- **Risks:** Rust core scope creep (§6 R5).
- **STOP — awaiting approval before M6**

### M6 — Mock Server, 18-Attack Suite, Reports
- **Goal:** Stage every attack locally and measure the system end to end.
- **Builds (impl refs):** §6.1, §6.2, §6.3; AttackEvidence from §2.1.
- **Tests (test refs):** §4.1 to §4.18, integration §5.3, benchmarks §6.1 to §6.3, aggregation §7.
- **Deliverables:** `mock_server/`, `tests/attacks/01..18_*.py`, `tests/benchmark/`, `tests/report.py`,
  `docs/reports/attacks_report.{md,json}`, and a populated README Benchmarks section.
- **Success criteria:** all 18 attacks fire and are caught at their expected layers (or documented as
  known-fail with the capability layer as backstop); guarded MCPTox ASR meets the < 5% target; clean
  traffic FP rate < 1%.
- **Complexity:** L
- **Dependencies:** M5 (full enforcement path required for real verdicts).
- **Risks:** MCPTox reproduction fidelity (§6 R2).
- **STOP — awaiting approval before M7**

### M7 — Frontend and Backend
- **Goal:** Build the six-page dashboard plus the API/WebSocket bridge, including the two required tabs.
- **Builds (impl refs):** §5.1, §5.2, §5.3, §5.4.
- **Tests (test refs):** frontend build and contract checks against §5.1; live traffic verified against
  integration §5.1 output.
- **Deliverables:** `frontend/` (Vite/React/TS app, six pages, tokens, theme), `backend/` (FastAPI REST
  + WebSocket).
- **Success criteria:** dashboard renders in light and dark with WCAG AA contrast; Live Traffic streams
  real verdicts; Attack Simulator fires a chosen attack and shows the live decision; Attack Workflow
  animates a triggered attack through the layers.
- **Complexity:** L
- **Dependencies:** M6 (needs real verdicts and attack triggers to visualize).
- **Risks:** design-reference alignment pending the shared dashboards (§8 Q6-adjacent).
- **STOP — awaiting approval before M8**

### M8 — Demo Polish
- **Goal:** Make the project reproducible and demo-ready.
- **Builds (impl refs):** ties together §3 and §5 via one-command startup; no new layer specs.
- **Tests (test refs):** final benchmark run §6.1 to §6.3; full attack suite §4 green.
- **Deliverables:** `docker-compose.yml`, `docs/demo/` (quick-demo GIF, full walkthrough, rehearsal
  script), `docs/threat_model.md`, final README pass with real numbers and wired demo links.
- **Success criteria:** a clean checkout runs with one `docker-compose up -d`; demo assets match the
  current UI; threat model is complete; the rehearsal script runs start to finish.
- **Complexity:** M
- **Dependencies:** M7.
- **STOP — awaiting approval before final delivery**

---

## §4 Data Sourcing Plan

Per dataset: source, size, license status, consuming milestone, and fallback if download fails. On-disk
schema and output paths are in impl §4.1.

| Dataset | URL | Size | License | Consumed by | Fallback |
|---------|-----|------|---------|-------------|----------|
| deepset/prompt-injections | huggingface.co/datasets/deepset/prompt-injections | ~660 | verify in M1 | M1 | none needed (small, open) |
| jackhhao/jailbreak-classification | huggingface.co/datasets/jackhhao/jailbreak-classification | ~1,306 | verify in M1 | M1 | none needed |
| allenai/wildjailbreak | huggingface.co/datasets/allenai/wildjailbreak | 262k | gated terms | M1 | proceed without; boost synthetic (§4.3) |
| MCPSecBench | github.com/AIS2Lab/MCPSecBench | 17 types | repo | M1, M6 | primary MCP corpus if MCPTox missing |
| MCP-SafetyBench | github.com/xjzzzzzzzz/MCPSafety | 20 types | repo (ICLR 2026) | M1, M6 | secondary MCP corpus |
| MCPTox | artifact from arXiv:2508.14925 | 1,312 | verify in M1 | M1, M6 | fall back to MCPSecBench + MCP-SafetyBench |
| OWASP MCP Top 10 | github.com/OWASP/www-project-mcp-top-10 | reference | open | M1 | none needed |
| Synthetic augmentation | local Ollama Llama 3.1 8B | 5x to 10x | generated locally | M1 | generate more to cover gaps |

---

## §5 Attack Reenactment Plan

Per attack: original incident, the mock-server tool that stages it, and the expected block layer. Full
staging detail is in impl §6.3; guarded/unguarded behavior and assertions are in test §4. All staged in
M6.

| # | Attack | Incident (README matrix) | Mock tool (impl §6.3) | Expected block layer |
|---|--------|--------------------------|-----------------------|----------------------|
| 1 | Tool description poisoning | Invariant Labs, Apr 2025 | repo.manifest | 5 (also 2a/4) |
| 2 | Rug-pull redefinition | CVE-2025-54136 | repo.manifest | 5 |
| 3 | Indirect prompt injection | OWASP / deepset | fs.read_file | 2a/2b/4 |
| 4 | Data exfiltration | WhatsApp exfil (Invariant/Docker) | fs.read_file | 2a/4 |
| 5 | Unicode tag-block smuggling | arXiv:2607.05744 | fs.read_file | 1.5 |
| 6 | Zero-width obfuscation | Unicode smuggling class | fs.search | 1.5 |
| 7 | Homoglyph substitution | confusable_homoglyphs research | web.fetch | 1.5 (also 2b) |
| 8 | Cross-call split payload | MCPSecBench multi-step | fs.search x3 | 3 |
| 9 | Secret / credential leak | gitleaks corpus | logs.tail | 2a |
| 10 | Phishing URL injection | OWASP MCP Top 10 | web.fetch | 2a/2b |
| 11 | OCR image injection | multimodal injection research | img.screenshot | 1 to 1.5 to 2a |
| 12 | Audio injection | multimodal injection research | audio.note | 1 (STT) to 2a |
| 13 | Jailbreak payload | jackhhao/jailbreak-classification | fs.read_file | 2b/4 |
| 14 | Schema drift | Invariant / Microsoft | repo.manifest | 5 |
| 15 | Confused-deputy exfil | GitHub MCP exfil (Invariant) | fs.read_file + chat.send | 3/4 |
| 16 | Denial-of-wallet | MCP cost-abuse class | web.fetch flood | 6 |
| 17 | Command / code injection | MCPSecBench tool-centric | fs.read_file | 2a/4 |
| 18 | PII harvesting | OWASP MCP Top 10 | fs.search | 2b/4 |

All staged data (secrets, PII, URLs, numbers) is synthetic and local. No real third-party service is
contacted.

---

## §6 Risk Register

| # | Risk | Impact | Mitigation |
|---|------|--------|------------|
| R1 | wildjailbreak gated / inaccessible | smaller M1 corpus | proceed with ungated sources, boost synthetic (impl §4.3), record the gap in DATA_CARD.md |
| R2 | MCPTox artifact URL not locatable | missing primary MCP corpus | fall back to MCPSecBench + MCP-SafetyBench (§4), flag in §8 Q1 before M1 |
| R3 | Local judge latency blows the budget | pipeline too slow to leave on | judges on the ~10% path only (impl §3.6), small models, Groq fallback, BLAKE3 verdict cache |
| R4 | DeBERTa underperforms on CPU | Judge C weak | fewer epochs / smaller head / pretrained variant; panel tolerates one weak judge (impl §3.6) |
| R5 | Rust core scope creep | M5 overruns | cap core < 5k LoC, keep detection in Python, core does interception and enforcement only (impl §3.0) |
| R6 | High false positive rate on clean traffic | alert fatigue, weak demo | clean hold-out from M1 (impl §4.2), tune thresholds, measure explicitly (test §6.3) |
| R7 | Docker model-pull time makes the demo fragile | Quick Start fails live | pin model versions, pre-pull in build, health-gate startup, document the ~2 min warm-up (M8) |
| R8 | OCR/STT defeated by adversarial media | Layer 1 misses hidden instructions | treat Layer 1 as best-effort (impl §3.1), rely on capability layer (impl §3.10) as backstop |

---

## §7 Out of Scope

What this project does not build. Each item is documented as future work or a containment boundary in
the referenced spec section.

- Detecting a compromised server that only misuses correctly granted permissions. Contained by the
  capability layer (impl §3.10 known limitations), not by content detection.
- Supply-chain analysis of MCP server binaries or dependencies.
- Network- or transport-level intrusion detection outside the MCP response path.
- A hardened multi-tenant production cluster; the personal profile is single-node (impl §3.9, §3.11
  enterprise notes).
- Cross-session and cross-tenant attack correlation (impl §3.5 known limitations; README Roadmap).
- Independent third-party audit of the benchmark numbers (README Limitations).
- Any required cloud dependency for core operation; Groq is an optional fallback only (impl §3.6).
- Any git, GitHub, or CI operation.

---

## §8 Open Questions

1. **MCPTox artifact location.** The paper is verified (arXiv:2508.14925) but the exact downloadable
   corpus repo needs confirming. Preferred source, or should M1 locate and record it? (Blocks the
   MCPTox portion of M1; MCPSecBench + MCP-SafetyBench are the fallback per §4.)
2. **wildjailbreak access.** This dataset is gated. Is there a HuggingFace token with terms accepted,
   or should M1 proceed without it and lean on synthetic augmentation?
3. **Judge hosting default.** Should the shipped default run judges via local Ollama (heavier local
   footprint, fully offline) or default to Groq free tier with Ollama optional? Affects the M8
   docker-compose footprint.
4. **Enterprise features.** Confirm SPIFFE, HSM, S3 Object Lock, and Redis stay documentation-only
   (impl enterprise notes) and out of the buildable milestones.
5. **Benchmark hardware.** Which machine runs the M6 benchmarks? This sets realistic latency targets
   before the placeholder tables in test §6.2 and the README are filled in.
6. **Design reference.** The card-based dashboard reference is to be shared separately. M7 needs it
   before the frontend is finalized; a text description is enough to start.
