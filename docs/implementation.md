# Trishul Implementation Specification

This is the build specification. It defines what to construct at every layer: inputs, outputs, config
knobs, error cases, and files. Testing is specified separately in `testing.md`. Milestone sequencing
is in `plan.md`. Sections are numbered so the other two documents can reference them without repeating
content.

Section map:

- §1 Overview
- §2 Shared Contracts (§2.1 Common Types, §2.2 DetectionRule, §2.3 ActionPolicy, §2.4 gRPC)
- §3 Layer-by-Layer Specifications (§3.0 through §3.11)
- §4 Data Pipeline (§4.1 acquisition, §4.2 preprocessing, §4.3 synthetic, §4.4 FAISS, §4.5 DeBERTa)
- §5 Frontend (§5.1 API, §5.2 pages, §5.3 design system, §5.4 theme)
- §6 Mock MCP Server (§6.1 tools, §6.2 payload catalog, §6.3 triggering)

---

## §1 Overview

Trishul is built as a thin Rust enforcement core wrapped around a set of fat Python detection workers.
The core (Layer 0, §3.0) does one job: intercept every MCP call and response, ask the workers for a
verdict over gRPC, and enforce that verdict. It holds no detection logic, stays under 5k lines, and is
the only component in the trust path that must be memory-safe and hard to bypass. Everything that
requires models, heuristics, or tuning lives in Python workers that can be developed, tested, and
replaced independently. This split keeps the security-critical surface small while letting the
detection logic evolve quickly.

Every layer is an independently testable unit with an explicit input contract and output contract
(§2.1). Detection logic is exposed through two Open-Closed interfaces, DetectionRule (§2.2) and
ActionPolicy (§2.3), so new rules and policies are added by writing a class, not by editing core code.
The system fails closed everywhere: any timeout, parse error, or worker outage produces a BLOCK or an
ESCALATE, never a silent ALLOW. No layer trusts its input, and no layer assumes a downstream layer
will catch what it misses. Each layer documents its own known limitations and names the layer that
picks up the slack.

---

## §2 Shared Contracts

### §2.1 Common Types

All workers import these from `workers/common/types.py`. They are Pydantic v2 models (frozen where
noted) so validation happens at the boundary and serialization to gRPC and JSON is uniform.

**ToolCallContext** — describes the call that produced a response. Frozen.

| Field | Type | Required | Example |
|-------|------|----------|---------|
| session_id | str (UUID) | yes | "9f2c..." |
| tool_name | str | yes | "github.read_file" |
| tool_description | str | yes | "Read a file from a repository" |
| agent_intent | str \| None | no | "summarize the README" |
| server_id | str | yes | "mock-github" |
| invocation_id | str (UUID) | yes | "a1b2..." |
| timestamp | datetime (UTC) | yes | 2026-09-13T10:00:00Z |

**ToolResponse** — the raw response under inspection. Frozen.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| raw_bytes | bytes | yes | Exact bytes returned by the MCP server |
| content_type | str | yes | MIME, e.g. "application/json", "image/png" |
| text_parts | list[str] | yes | Text extracted at parse time (may be empty) |
| media_parts | list[MediaPart] | yes | Images/audio for Layer 1 (may be empty) |

**MediaPart** — `{ kind: "image"|"audio", mime: str, data: bytes, part_id: str }`.

**LayerVerdict** — what every layer returns. Frozen.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| layer_id | str | yes | "1.5", "2a", "4", etc. |
| decision | enum | yes | ALLOW \| BLOCK \| ESCALATE \| PASS_THROUGH |
| confidence | float [0,1] | yes | 1.0 for deterministic layers |
| reason | str | yes | Stable machine slug, e.g. "unicode_tag_smuggling" |
| matched_spans | list[Span] | no | `{ start:int, end:int, text:str, source:"raw"|"decoded"|"ocr"|"stt" }` |
| latency_ms | float | yes | Measured wall-clock in the layer |
| metadata | dict[str, Any] | no | Layer-specific extras |

`PASS_THROUGH` means "this layer found nothing and expresses no opinion." Only the Policy Engine
(§3.9) emits a final ALLOW/BLOCK/ESCALATE for forwarding; layers emit their local view.

**PolicyVerdict** — the final decision. Frozen.

| Field | Type | Notes |
|-------|------|-------|
| final_decision | enum | ALLOW \| BLOCK \| ESCALATE |
| contributing_verdicts | list[LayerVerdict] | Every layer that ran |
| signed_payload | bytes | Ed25519 signature over the canonical verdict (§3.9) |
| verdict_hash | str | BLAKE3 of the canonical verdict body |
| timestamp | datetime (UTC) | Decision time |

**AttackEvidence** — emitted for the test suite and the dashboard. Frozen.

| Field | Type | Notes |
|-------|------|-------|
| attack_class | str | One of the 18 taxonomy slugs (§4.2) |
| layer_caught_at | str \| None | Layer id, or None if it leaked |
| payload_preview | str | Truncated, redacted preview (max 200 chars) |
| blocked_at_layer | str \| None | Same as layer_caught_at when blocked |

### §2.2 DetectionRule Interface (OCP)

Location: `workers/common/detection_rule.py`. Every rule inside Layers 2a, 2b, 3, 5, and 6 implements
this so new detections are added without editing layer orchestration.

```python
class DetectionRule(ABC):
    rule_id: str          # stable unique slug, e.g. "aho.exfil_send_to"
    layer_id: str         # layer this rule belongs to
    default_enabled: bool

    @abstractmethod
    def evaluate(self, text: str, ctx: ToolCallContext) -> LayerVerdict:
        """Inspect canonical text for one attack signal.

        Must be pure and side-effect free. Must return a LayerVerdict with
        this rule's layer_id and a stable reason slug. Must NOT raise for
        normal input; on unexpected internal error it returns a BLOCK verdict
        with reason 'rule_internal_error' (fail closed), never PASS_THROUGH.
        Must respect its own time budget and return within the layer timeout.
        """
```

Example stub: `AhoExfilRule(DetectionRule)` scans for exfiltration verbs and returns
`decision=BLOCK, reason="exfiltration_instruction"` with matched spans, else `PASS_THROUGH`.

### §2.3 ActionPolicy Interface (OCP)

Location: `workers/common/action_policy.py`. The Policy Engine (§3.9) loads an ordered list of these
to turn layer verdicts into a final decision.

```python
class ActionPolicy(ABC):
    policy_id: str
    priority: int   # lower runs first; first decisive policy wins

    @abstractmethod
    def decide(self, verdicts: list[LayerVerdict], ctx: ToolCallContext
               ) -> PolicyDecision | None:
        """Return a decision, or None to defer to the next policy.

        PolicyDecision = { decision: ALLOW|BLOCK|ESCALATE, reason: str,
        contributing: list[str] (rule/layer ids) }. Returning None means 'no
        opinion'. If every policy returns None, the engine defaults to BLOCK
        (fail closed) with reason 'no_policy_matched'. Must never raise; on
        internal error it returns BLOCK.
        """
```

### §2.4 gRPC Service Definitions

Reference: `core/proto/trishul.proto`. The Rust core is the client; Python workers host the service.
Transport is gRPC over mTLS (§3.0). Messages mirror §2.1 types.

| RPC | Request | Response | Notes |
|-----|---------|----------|-------|
| InspectResponse | ToolResponse, ToolCallContext | LayerVerdict (final, from Policy) | The main hot path |
| GetSchemaFingerprint | tool_name: str | SchemaFingerprint `{ hash, captured_at, field_count }` | Layer 5 (§3.7) |
| RecordCallMetrics | server_id, session_id, latency_ms, decision | Ack `{ ok: bool }` | Layer 6 (§3.8) |
| ValidateToken | jwt_token: str, invocation_id: str | ValidationResult `{ valid: bool, reason: str }` | Capability (§3.10) |

Deadlines: InspectResponse carries a hard 2000 ms deadline set by the core. If the deadline is hit,
the core treats it as BLOCK (fail closed, §3.0).

---

## §3 Layer-by-Layer Specifications

### §3.0 Layer 0 — Reference Monitor

**Purpose.** The single enforcement point. It intercepts every MCP call and response, requests a
verdict from the worker pipeline, and enforces ALLOW/BLOCK/ESCALATE. It addresses no attack class
directly; it is the mechanism that makes every other layer's verdict binding and unbypassable.

**Position in pipeline.** Sits between the agent and the MCP server. Feeds the whole worker pipeline
via `InspectResponse` (§2.4). Runs Layer 5 (§3.7) and Layer 6 (§3.8) hooks on the request side before
forwarding.

**Input contract.** On the request side: the raw MCP call plus a capability token. On the response
side: raw server bytes assembled into a ToolResponse (§2.1) with a ToolCallContext.

**Output contract.** Forwarded bytes (on ALLOW), a redacted response with a machine-readable block
reason (on BLOCK), or a held response with a pending marker (on ESCALATE). Emits a RecordCallMetrics
call (§2.4) for every decision.

**Configuration.** `core/config.toml`: `inspect_deadline_ms` (default 2000), `fail_mode` (default
"closed"), `mtls_cert_path`, `mtls_key_path`, `worker_endpoint`, `max_response_bytes` (default
10_000_000).

**Algorithm / logic.**
1. Receive an MCP call from the agent. Extract the capability token.
2. Call ValidateToken (§2.4, §3.10). If invalid or expired, BLOCK with reason "invalid_token".
3. Call GetSchemaFingerprint (§3.7). If drift is detected, BLOCK with reason "schema_drift".
4. Forward the call to the MCP server. Record start time for Layer 6.
5. Receive the raw response. If larger than `max_response_bytes`, BLOCK with reason "response_too_large".
6. Assemble ToolResponse and ToolCallContext. Call InspectResponse with the 2000 ms deadline.
7. On ALLOW, forward the response to the agent. On BLOCK, return a redacted response and the reason.
   On ESCALATE, hold and return a pending marker.
8. Call RecordCallMetrics with the final decision and measured latency.

**Failure modes.**
- InspectResponse deadline exceeded → BLOCK, reason "inspect_timeout".
- Worker unreachable → BLOCK, reason "worker_unavailable".
- mTLS handshake failure → refuse to start; do not run in an unauthenticated state.
- Malformed MCP frame → BLOCK, reason "frame_parse_error".

**Latency budget.** Core overhead only (excludes worker time): P50 < 0.5 ms, P95 < 1 ms, P99 < 2 ms.
Exceeding it is a performance bug, not a security failure; the deadline still bounds total time.

**Dependencies.** Rust stable, tonic (gRPC), rustls (mTLS), prost (protobuf), blake3 crate.

**Files to create.** `core/src/main.rs` (bootstrap), `core/src/interceptor.rs` (call/response
capture), `core/src/enforce.rs` (verdict application and redaction), `core/src/grpc_client.rs`,
`core/src/mtls.rs`, `core/proto/trishul.proto`, `core/config.toml`.

**Cross-references.** Tests: testing.md §3.0, §5.1, §5.2. Milestone: plan.md §3 M5.

**Known limitations.** Does not inspect content itself; a bug in a worker that returns ALLOW is
enforced faithfully. Mitigated by the fail-closed default and by Layer 4 independence (§3.6).

### §3.1 Layer 1 — Media Extraction

**Purpose.** Convert images and audio inside a response into text so that instructions hidden in
non-text media become visible to the text layers. Addresses attack classes 11 (OCR image injection)
and 12 (audio injection); assists 4 and 17 when payloads arrive as media.

**Position in pipeline.** First worker layer. Consumes ToolResponse.media_parts, produces text that is
concatenated with ToolResponse.text_parts and handed to Layer 1.5 (§3.2).

**Input contract.** `media_parts: list[MediaPart]` and `text_parts: list[str]` from ToolResponse
(§2.1). Media parts may be empty, in which case this layer is a fast pass-through.

**Output contract.** `ExtractedText { text_parts: list[str], extracted: list[{ part_id, source:
"ocr"|"stt", text, confidence }], any_media: bool }`. Emits a LayerVerdict with
`decision=PASS_THROUGH` unless extraction fails.

**Configuration.** `config/layer1.yaml`: `ocr_lang` (default "eng"), `ocr_timeout_ms` (default 800),
`stt_model` (default "whisper-base"), `stt_timeout_ms` (default 5000), `max_image_px` (default
4_000_000), `enable_stt` (default true).

**Algorithm / logic.**
1. If `media_parts` is empty, return PASS_THROUGH immediately with the original text_parts.
2. For each image part: decode with Pillow, downscale if above `max_image_px`, run Tesseract OCR.
3. For each audio part: run Whisper STT to a transcript.
4. Attach every extraction with its source tag and confidence to the output.
5. Concatenate original text with extracted text for downstream layers.

**Failure modes.**
- OCR/STT timeout → BLOCK, reason "media_extract_timeout" (fail closed: unreadable media is treated as
  hostile).
- Unsupported or corrupt media → BLOCK, reason "media_decode_error".
- Whisper model missing → BLOCK, reason "worker_unavailable".

**Latency budget.** Text-only responses: P95 < 1 ms (pass-through). With one image: P95 < 800 ms. With
audio: P95 < 5000 ms. These paths are on the "+media" latency lane in testing.md §6.2.

**Dependencies.** pytesseract + Tesseract binary, openai-whisper (whisper-base), Pillow, numpy.

**Files to create.** `workers/layer1_extraction/ocr.py`, `workers/layer1_extraction/stt.py`,
`workers/layer1_extraction/service.py`, `config/layer1.yaml`.

**Cross-references.** Tests: testing.md §3.1, attacks §4.11 and §4.12. Milestone: plan.md §3 M2.

**Known limitations.** Adversarially perturbed images or noisy audio may defeat extraction. When text
is not recovered, the hidden instruction is invisible to later layers; the capability layer (§3.10) is
the backstop.

### §3.2 Layer 1.5 — Normalization and De-obfuscation

**Purpose.** Produce one canonical text form so obfuscated payloads cannot slip past pattern and
semantic layers. Addresses classes 5 (tag-block smuggling), 6 (zero-width), and 7 (homoglyph); assists
every text-based class by normalizing input.

**Position in pipeline.** Consumes the concatenated text from Layer 1 (§3.1). Feeds Layer 2a (§3.3).
Its canonical output is also the exact text used for training data (§4.2) so train and inference match.

**Input contract.** `{ text: str, from_media: bool }`.

**Output contract.** `CanonicalText { text: str, was_obfuscated: bool, original_len: int,
stripped_len: int, transformations: list[str] }`. LayerVerdict is PASS_THROUGH; `was_obfuscated` is a
signal for later layers, not a block on its own.

**Configuration.** `config/layer1_5.yaml`: `strip_ranges` (default list below), `base64_min_len`
(default 20), `base64_recurse_depth` (default 3), `nfkc` (default true), `timeout_ms` (default 3).

**Algorithm / logic.**
1. Receive raw text and any text extracted by Layer 1.
2. Concatenate both into one working string.
3. Apply `unicodedata.normalize('NFKC', text)` to collapse homoglyphs and compatibility forms.
4. Strip characters in ranges: U+200B to U+200F, U+FEFF, U+E0000 to U+E007F, U+202A to U+202E,
   U+2066 to U+2069.
5. Detect base64 blocks (pattern `^[A-Za-z0-9+/=]{20,}$`). Decode each and recurse into steps 3 and 4
   on the decoded content. Depth limit 3.
6. Compute `was_obfuscated`: true if any characters were stripped or any base64 block decoded to
   non-ASCII.
7. Return canonical text, the flag, original length, and stripped length.

**Failure modes.**
- Malformed UTF-8 → BLOCK, reason "encoding_error".
- Recursion or size blow-up beyond limits → stop recursion, keep what was decoded, set
  `was_obfuscated=true`.
- Timeout → BLOCK, reason "normalize_timeout".

**Latency budget.** P50 < 1 ms, P95 < 3 ms, P99 < 5 ms on inputs up to 100 KB.

**Dependencies.** Standard library `unicodedata`, `confusable_homoglyphs`, `base64`.

**Files to create.** `workers/layer1_5_normalize/normalize.py`,
`workers/layer1_5_normalize/homoglyph.py`, `workers/layer1_5_normalize/service.py`,
`config/layer1_5.yaml`.

**Cross-references.** Tests: testing.md §3.2, attacks §4.5, §4.6, §4.7. Milestone: plan.md §3 M2.

**Known limitations.** Does not judge intent; a de-obfuscated string still needs Layer 2a/2b/4 to
decide whether it is an attack. Novel obfuscation schemes outside the strip ranges are not handled.

### §3.3 Layer 2a — Pattern Match

**Purpose.** Linear-time detection of known malicious signatures and secrets. Addresses classes 3, 4,
9, 10, 17 with high precision at near-zero cost.

**Position in pipeline.** Consumes CanonicalText from Layer 1.5 (§3.2). Feeds Layer 2b (§3.4). First
layer that can emit BLOCK.

**Input contract.** `CanonicalText` (§3.2 output).

**Output contract.** LayerVerdict with `layer_id="2a"`, decision BLOCK on any signature hit else
PASS_THROUGH, `matched_spans` populated, `reason` the hitting rule's slug.

**Configuration.** `config/layer2a.yaml`: `signature_set_path`, `secret_patterns_path` (gitleaks-style),
`case_insensitive` (default true), `timeout_ms` (default 5), `enabled_rules` (list).

**Algorithm / logic.**
1. Load the compiled Aho-Corasick automaton from the signature set at startup.
2. Run the automaton over the canonical text in one pass, collecting all matches with offsets.
3. Run the secret-pattern DetectionRules (§2.2) for API keys, tokens, and private keys.
4. If any match, return BLOCK with the first (highest-priority) rule's reason and all matched spans.
5. Else PASS_THROUGH.

**Failure modes.**
- Signature set fails to load at startup → refuse to start (fail closed).
- Timeout → BLOCK, reason "pattern_timeout".

**Latency budget.** P50 < 0.3 ms, P95 < 1 ms independent of pattern count (linear in text length).

**Dependencies.** pyahocorasick, Python `regex` module, gitleaks pattern list (vendored).

**Files to create.** `workers/layer2a_patterns/automaton.py`, `workers/layer2a_patterns/secrets.py`,
`workers/layer2a_patterns/rules/`, `workers/layer2a_patterns/service.py`, `config/layer2a.yaml`,
`data/signatures/signatures.txt`.

**Cross-references.** Tests: testing.md §3.3, attacks §4.3, §4.4, §4.9, §4.10, §4.17. Milestone:
plan.md §3 M2.

**Known limitations.** Exact/substring matching only. Paraphrased or novel attacks pass through to
Layer 2b (§3.4) and Layer 4 (§3.6).

### §3.4 Layer 2b — Semantic Similarity

**Purpose.** Catch paraphrased and previously unseen attacks by nearest-neighbor similarity to a known
malicious corpus. Addresses classes 3, 7, 10, 13, 18 and any paraphrase that dodges Layer 2a.

**Position in pipeline.** Consumes CanonicalText (§3.2), runs after Layer 2a (§3.3) passes. Feeds
Layer 3 (§3.5). Marks ambiguous cases for escalation to Layer 4 (§3.6).

**Input contract.** `CanonicalText` plus the Layer 2a verdict (for context).

**Output contract.** LayerVerdict `layer_id="2b"`, decision BLOCK if `top_score >= block_threshold`,
ESCALATE if `escalate_threshold <= top_score < block_threshold`, else PASS_THROUGH. Metadata carries
`top_score`, `neighbor_class`, `neighbor_id`.

**Configuration.** `config/layer2b.yaml`: `model` (default "all-MiniLM-L6-v2"), `index_path`,
`block_threshold` (default 0.85), `escalate_threshold` (default 0.70), `top_k` (default 5),
`efSearch` (default 64), `timeout_ms` (default 40).

**Algorithm / logic.**
1. Load the MiniLM model and the FAISS HNSW index (§4.4) at startup.
2. Split the canonical text into overlapping windows (sentence or 256-token chunks).
3. Embed each window; query the FAISS index for top_k neighbors.
4. Take the maximum cosine similarity across windows as `top_score` and record the neighbor's class.
5. Map `top_score` to BLOCK / ESCALATE / PASS_THROUGH via thresholds.

**Failure modes.**
- Index or model missing → refuse to start (fail closed).
- Timeout → ESCALATE, reason "semantic_timeout" (defer to judges rather than hard-block).

**Latency budget.** P50 < 15 ms, P95 < 40 ms, P99 < 60 ms per response at 100k+ vectors.

**Dependencies.** sentence-transformers, faiss-cpu, PyTorch (CPU), numpy.

**Files to create.** `workers/layer2b_semantic/embed.py`, `workers/layer2b_semantic/search.py`,
`workers/layer2b_semantic/service.py`, `config/layer2b.yaml`.

**Cross-references.** Tests: testing.md §3.4, attacks §4.3, §4.7, §4.10, §4.13, §4.18. Milestone:
plan.md §3 M2. Index build: §4.4.

**Known limitations.** Similarity is only as good as the corpus. Truly novel attack phrasings score low
and rely on Layer 4 (§3.6). Threshold tuning trades false positives against false negatives; measured
in testing.md §6.3.

### §3.5 Layer 3 — Cross-Call Aggregator

**Purpose.** Detect payloads deliberately split across multiple responses in a session that each look
benign in isolation. Addresses classes 8 (split payload) and 15 (confused-deputy cross-server).

**Position in pipeline.** Consumes canonical text plus the per-response verdicts; maintains a
per-session encrypted buffer. Feeds the Policy Engine (§3.9).

**Input contract.** `{ session_id, canonical_text, per_response_verdicts: list[LayerVerdict] }`.

**Output contract.** LayerVerdict `layer_id="3"`, decision BLOCK if reassembled content crosses a
threat threshold, else PASS_THROUGH. Metadata carries `reassembled_score`, `contributing_response_ids`.

**Configuration.** `config/layer3.yaml`: `window_size` (default 8 responses), `ttl_seconds` (default
300), `reassembly_threshold` (default 0.85), `aes_key_source` (default "local_keystore"),
`max_buffer_bytes_per_session` (default 1_000_000).

**Algorithm / logic.**
1. Append the new canonical text to the session buffer, encrypted at rest with AES-GCM.
2. Reassemble the sliding window (last `window_size` responses) into a candidate string.
3. Re-run Layer 2a (§3.3) signatures and Layer 2b (§3.4) similarity over the reassembled candidate.
4. If the reassembled score crosses `reassembly_threshold` while individual responses did not, BLOCK.
5. Evict buffer entries older than `ttl_seconds` or beyond the size cap.

**Failure modes.**
- Session store unavailable → ESCALATE, reason "aggregator_unavailable".
- Decryption failure on buffer read → BLOCK, reason "buffer_integrity_error".

**Latency budget.** P50 < 3 ms, P95 < 5 ms (excludes re-run of 2a/2b, which reuse their budgets).

**Dependencies.** cryptography (AES-GCM), the Layer 2a and 2b workers, in-memory store (personal) or
Redis (enterprise).

**Files to create.** `workers/layer3_aggregator/buffer.py`, `workers/layer3_aggregator/reassemble.py`,
`workers/layer3_aggregator/service.py`, `config/layer3.yaml`.

**Cross-references.** Tests: testing.md §3.5, attacks §4.8, §4.15, integration §5.3. Milestone:
plan.md §3 M4.

**Known limitations.** Buffering is session-scoped and time-bounded. Payloads split across sessions or
across windows longer than the TTL evade this layer in the personal profile.

### §3.6 Layer 4 — AI Judge Panel

**Purpose.** Adjudicate the roughly 10% of cases the deterministic and semantic layers mark ambiguous,
using independent judges to reduce the chance a single model is fooled. Addresses novel and paraphrased
variants of classes 1, 3, 4, 13, 15, 17, 18.

**Position in pipeline.** Invoked by the Policy Engine (§3.9) only when an upstream verdict is
ESCALATE. Returns a consensus verdict to the Policy Engine and writes judge votes to the Audit log
(§3.11).

**Input contract.** `{ canonical_text, ctx: ToolCallContext, upstream_verdicts: list[LayerVerdict] }`.

**Output contract.** LayerVerdict `layer_id="4"`, decision BLOCK or ALLOW (never ESCALATE; the panel
is the tiebreaker), confidence = agreement ratio, metadata carries per-judge votes `{ A, B, C, D }`.

**Configuration.** `config/layer4.yaml`: `judges` (A, B, C, D toggles), `ollama_endpoint`, `groq_fallback`
(default true), `consensus_rule` (default "weighted_majority"), `deberta_model_path`,
`judge_timeout_ms` (default 1500), `degraded_lane` (default true), `sensitive_verbs` (list).

**Algorithm / logic.**
1. Fan out the canonical text to the enabled judges in parallel: A (Llama 3.1 8B), B (Qwen 2.5 7B),
   C (fine-tuned DeBERTa-v3, §4.5), D (deterministic regex/gitleaks).
2. Each judge returns a structured verdict validated against a JSON schema (label + confidence).
3. Combine votes with the consensus rule. Judge D is a hard veto for confirmed secrets.
4. If judges are unavailable and `degraded_lane` is on, apply the degraded rule: BLOCK when the call
   is ambiguous and the tool verb is in `sensitive_verbs`; ALLOW clean; otherwise ESCALATE to a human.
5. Cache the verdict keyed by BLAKE3 of the canonical text to avoid re-judging identical content.

**Failure modes.**
- One judge times out → proceed with the remaining judges; note the dropout in metadata.
- All generative judges down → degraded lane (step 4).
- Structured-output parse failure from a judge → treat that judge as a BLOCK vote (fail closed).

**Latency budget.** Only on the escalation lane. P50 < 400 ms, P95 < 1200 ms, P99 < 1500 ms with local
Ollama; Groq fallback typically faster.

**Dependencies.** Ollama (llama3.1:8b, qwen2.5:7b), transformers + the fine-tuned DeBERTa, Jinja2
(prompts), Pydantic (structured output), optional Groq client.

**Files to create.** `workers/layer4_judges/ollama_client.py`, `workers/layer4_judges/deberta.py`,
`workers/layer4_judges/regex_judge.py`, `workers/layer4_judges/consensus.py`,
`workers/layer4_judges/prompts/`, `workers/layer4_judges/service.py`, `config/layer4.yaml`.

**Cross-references.** Tests: testing.md §3.6, integration §5.2 (degraded mode). Milestone: plan.md §3
M3. Training: §4.5.

**Known limitations.** Judges are small local models chosen for independence and cost, not
state-of-the-art reasoning. A carefully crafted prompt can fool the panel; the capability layer
(§3.10) bounds the outcome.

### §3.7 Layer 5 — Schema Drift

**Purpose.** Detect silent tool-description poisoning and rug-pulls by comparing the current tool
manifest against an approved snapshot. Addresses classes 1 (description poisoning) and 2/14 (rug-pull,
schema drift).

**Position in pipeline.** Runs on the request side inside the Reference Monitor (§3.0) via
GetSchemaFingerprint (§2.4), in parallel to the response pipeline. Feeds the Policy Engine (§3.9).

**Input contract.** `tool_name: str` and the live tool manifest captured at call time.

**Output contract.** `SchemaFingerprint { hash, captured_at, field_count }` plus a LayerVerdict
`layer_id="5"`, decision BLOCK on drift from the approved snapshot, else PASS_THROUGH. Metadata carries
a `jsondiff` summary.

**Configuration.** `config/layer5.yaml`: `snapshot_store_path`, `ignore_fields` (default: cosmetic
whitespace only), `block_on_description_change` (default true), `block_on_param_change` (default true).

**Algorithm / logic.**
1. On first approval of a tool, store a snapshot: canonicalized manifest, BLAKE3 hash, field count.
2. On each call, canonicalize the live manifest and compute its BLAKE3 hash.
3. If the hash differs, run jsondiff to classify the change (description, params, or cosmetic).
4. Cosmetic-only changes PASS_THROUGH; description or parameter changes BLOCK with a diff summary.

**Failure modes.**
- No snapshot exists (first sight) → PASS_THROUGH and record the snapshot; do not block first use.
- Snapshot store unavailable → BLOCK, reason "schema_store_unavailable".

**Latency budget.** P50 < 1 ms, P95 < 2 ms.

**Dependencies.** jsondiff, blake3, the snapshot store (SQLite personal, Redis/DB enterprise).

**Files to create.** `workers/layer5_schema/snapshot.py`, `workers/layer5_schema/diff.py`,
`workers/layer5_schema/service.py`, `config/layer5.yaml`.

**Cross-references.** Tests: testing.md §3.7, attacks §4.1, §4.2, §4.14. Milestone: plan.md §3 M4.

**Known limitations.** Detects change, not intent; a legitimate tool update is flagged and must be
re-approved. This is intentional (fail closed on drift).

### §3.8 Layer 6 — Rate and Anomaly

**Purpose.** Detect denial-of-wallet floods and abnormal call patterns that try to burn the judge
budget or probe the pipeline. Addresses class 16 (denial-of-wallet).

**Position in pipeline.** Fed by RecordCallMetrics (§2.4) from the Reference Monitor (§3.0). Advises
the Policy Engine (§3.9), primarily by throttling escalation to Layer 4 (§3.6).

**Input contract.** `{ server_id, session_id, latency_ms, decision, timestamp }` per call.

**Output contract.** LayerVerdict `layer_id="6"`, decision ESCALATE or PASS_THROUGH plus an
`anomaly_score`. On sustained anomaly it advises the Policy Engine to rate-limit judge escalation.

**Configuration.** `config/layer6.yaml`: `window_seconds` (default 60), `contamination` (default 0.02),
`escalation_rate_cap` (default 20 per minute per session), `retrain_interval_minutes` (default 30).

**Algorithm / logic.**
1. Maintain rolling per-session and per-server call-rate features (count, escalate ratio, latency
   spread) in a sliding window.
2. Score each new call with an IsolationForest trained on recent normal traffic.
3. If the score crosses the anomaly boundary, raise `anomaly_score` and advise rate-limiting.
4. Enforce `escalation_rate_cap`: beyond the cap, ambiguous cases are held (ESCALATE to human) rather
   than sent to the paid/costly judges.
5. Periodically retrain the IsolationForest on the latest normal window.

**Failure modes.**
- Model not yet trained (cold start) → PASS_THROUGH with a "warming_up" note; rate cap still applies.
- Feature store unavailable → apply a static rate cap only.

**Latency budget.** P50 < 2 ms, P95 < 3 ms.

**Dependencies.** scikit-learn (IsolationForest), pandas, numpy.

**Files to create.** `workers/layer6_anomaly/features.py`, `workers/layer6_anomaly/model.py`,
`workers/layer6_anomaly/service.py`, `config/layer6.yaml`.

**Cross-references.** Tests: testing.md §3.8, attacks §4.16. Milestone: plan.md §3 M4.

**Known limitations.** Statistical detection can be evaded by a slow, low-rate attacker. The static
rate cap is the floor of protection.

### §3.9 Policy Engine

**Purpose.** Combine every layer's verdict into one final signed ALLOW/BLOCK/ESCALATE. It is where
escalation to Layer 4 (§3.6) is decided and where the fail-closed default lives.

**Position in pipeline.** Terminal decision point. Consumes all LayerVerdicts, may call Layer 4, emits
a PolicyVerdict to the Reference Monitor (§3.0) and the Audit log (§3.11).

**Input contract.** `list[LayerVerdict]` from layers 1.5, 2a, 2b, 3, 5, 6 plus ToolCallContext.

**Output contract.** PolicyVerdict (§2.1), Ed25519-signed.

**Configuration.** `config/policy.yaml`: ordered `policies` (list of ActionPolicy ids, §2.3),
`default_decision` (default BLOCK), `escalate_on` (score band that triggers Layer 4), `signer_key_path`.

**Algorithm / logic.**
1. Collect all layer verdicts. If any layer returned BLOCK, run BLOCK-priority policies first.
2. If the strongest signal is ambiguous (a 2b ESCALATE band, or judge-requested), call Layer 4 (§3.6).
3. Evaluate ActionPolicies in priority order (§2.3); the first decisive decision wins.
4. If no policy is decisive, apply `default_decision` (BLOCK).
5. Canonicalize the verdict, hash it with BLAKE3, sign with Ed25519, emit PolicyVerdict.

**Failure modes.**
- Signer key missing → refuse to start (fail closed).
- Policy raises → treat as no-opinion; default applies.

**Latency budget.** P50 < 0.5 ms, P95 < 1 ms (excludes any Layer 4 call).

**Dependencies.** cryptography (Ed25519), blake3, the ActionPolicy set.

**Files to create.** `policy/engine.py`, `policy/policies/`, `policy/signer.py`, `config/policy.yaml`.

**Cross-references.** Tests: testing.md §3.9, integration §5.1. Milestone: plan.md §3 M5.

**Known limitations.** Only as good as its policies. New attack combinations may need a new
ActionPolicy (§2.3), which is the intended extension path.

### §3.10 Capability Layer

**Purpose.** Bound blast radius by issuing short-lived, narrowly scoped tokens the agent must present
per call, so a payload that evades detection still cannot perform an out-of-scope action. This is the
containment backstop for every "known limitation" above.

**Position in pipeline.** Parallel path. Mints tokens consumed by the Reference Monitor (§3.0) at
ValidateToken time (§2.4).

**Input contract.** `{ invocation_id, requested_scope: list[str], ttl_seconds }`.

**Output contract.** A signed JWT (Ed25519) bound to a single invocation_id and scope, plus a
ValidationResult on check.

**Configuration.** `config/capability.yaml`: `default_ttl_seconds` (default 30), `signer` (PyJWT
Ed25519 personal; SPIFFE/SPIRE enterprise), `scope_catalog`, `clock_skew_seconds` (default 2).

**Algorithm / logic.**
1. On call authorization, mint a JWT bound to the invocation_id with the minimal scope for the verb.
2. Set expiry to `default_ttl_seconds` (30 s).
3. On ValidateToken, verify signature, invocation_id match, scope sufficiency, and expiry.
4. Reject reuse across invocations and any use after expiry.

**Failure modes.**
- Signature invalid or scope insufficient → ValidationResult invalid, reason "scope_denied".
- Expired → invalid, reason "token_expired".
- Clock skew beyond tolerance → invalid, reason "token_not_yet_valid".

**Latency budget.** Mint and validate each P95 < 5 ms.

**Dependencies.** PyJWT (Ed25519), optional SPIFFE/SPIRE (enterprise).

**Files to create.** `policy/capability.py`, `policy/scopes.py`, `config/capability.yaml`.

**Cross-references.** Tests: testing.md §3.10, integration §5.5. Milestone: plan.md §3 M5.

**Known limitations.** Cannot stop misuse that stays within a correctly granted scope; that case is
out of scope for detection (plan.md §7) and is the reason scopes are kept minimal.

### §3.11 Audit

**Purpose.** Produce a tamper-evident forensic record of every verdict and every judge vote, so any
post-incident review can trust the log and detect tampering.

**Position in pipeline.** Sink. Consumes PolicyVerdicts (§3.9) and Layer 4 votes (§3.6).

**Input contract.** PolicyVerdict plus optional judge-vote metadata.

**Output contract.** An append-only, HMAC-chained record. Each entry stores the previous entry's HMAC,
so any edit breaks the chain from that point forward.

**Configuration.** `config/audit.yaml`: `db_path` (SQLite personal), `hmac_key_source`,
`external_signer` (default true), `worm_backend` (S3 Object Lock, enterprise).

**Algorithm / logic.**
1. Serialize the verdict canonically; compute an HMAC over (entry body + previous entry HMAC).
2. Append the entry and its HMAC to the store.
3. Periodically have an external signer sign the current chain head.
4. Provide a verify routine that walks the chain and reports the first broken link, if any.

**Failure modes.**
- Store write failure → BLOCK the originating call (fail closed: no unaudited allows).
- HMAC key missing → refuse to start.

**Latency budget.** P50 < 2 ms, P95 < 4 ms.

**Dependencies.** SQLite, cryptography (HMAC + external signer), optional S3 (enterprise).

**Files to create.** `audit/chain.py`, `audit/store.py`, `audit/verify.py`, `audit/service.py`,
`config/audit.yaml`.

**Cross-references.** Tests: testing.md §3.11, integration §5.4. Milestone: plan.md §3 M5.

**Known limitations.** Detects tampering after the fact; it does not prevent an attacker with write
access from truncating the log. Enterprise WORM storage closes this gap.

---

## §4 Data Pipeline Specification

### §4.1 Dataset acquisition

Per dataset: source, download command, expected size, license status, gating, output path, schema. The
sourcing table with fallbacks is in plan.md §4; this section defines the on-disk result each download
must produce.

| Dataset | Download | Output path | Expected rows | Raw schema |
|---------|----------|-------------|---------------|------------|
| deepset/prompt-injections | `hf download deepset/prompt-injections --repo-type dataset` | data/raw/prompt-injections/ | ~660 | text, label |
| jackhhao/jailbreak-classification | `hf download jackhhao/jailbreak-classification --repo-type dataset` | data/raw/jailbreak/ | ~1,306 | prompt, type |
| allenai/wildjailbreak | `hf download allenai/wildjailbreak --repo-type dataset` (gated, token) | data/raw/wildjailbreak/ | 262k | vanilla/adversarial pairs |
| MCPSecBench | `git clone https://github.com/AIS2Lab/MCPSecBench` | data/raw/mcpsecbench/ | 17 attack types | repo-defined |
| MCP-SafetyBench | `git clone https://github.com/xjzzzzzzzz/MCPSafety` | data/raw/mcp-safetybench/ | 20 attack types | repo-defined |
| MCPTox | artifact repo from arXiv:2508.14925 (confirm URL, plan.md §8) | data/raw/mcptox/ | 1,312 cases | repo-defined |
| OWASP MCP Top 10 | `git clone https://github.com/OWASP/www-project-mcp-top-10` | data/raw/owasp-mcp-top10/ | reference text | markdown |

Every license is re-verified and recorded in `data/DATA_CARD.md` before use. Gated datasets require an
authenticated HuggingFace token; if unavailable, the pipeline proceeds without them and records the gap.

### §4.2 Preprocessing

Output: `data/processed/{train,val,test}.jsonl`, each row `{ text, label, source, blake3, synthetic }`.

The 18-class taxonomy plus benign (labels): `tool_description_poisoning`, `rugpull_redefinition`,
`indirect_prompt_injection`, `data_exfiltration`, `unicode_tag_smuggling`, `zero_width_obfuscation`,
`homoglyph_substitution`, `cross_call_split_payload`, `secret_credential_leak`, `phishing_url_injection`,
`ocr_image_injection`, `audio_injection`, `jailbreak_payload`, `schema_drift`, `confused_deputy_exfil`,
`denial_of_wallet`, `command_code_injection`, `pii_harvesting`, `benign`.

Steps:
1. Load raw sources into a common `{ text, source_label, source }` frame.
2. Map every source label onto the taxonomy above; drop rows that cannot be mapped confidently.
3. Deduplicate by BLAKE3 hash of the canonical text.
4. Apply Layer 1.5 canonicalization (§3.2) so training text matches inference-time text exactly.
5. Stratified 80/10/10 split by label, seeded (`seed=1729`), with a hard rule: no synthetic example
   (§4.3) ever appears in val or test.
6. Reserve a separate clean-traffic hold-out of benign tool responses for false-positive measurement
   (testing.md §6.3).

### §4.3 Synthetic augmentation

Generator: local Ollama Llama 3.1 8B. Output tagged `synthetic=true`, train split only.

Prompt template (stored at `data/synth/prompt.jinja`): "You are generating labeled security test data
for an MCP response firewall. Produce {n} distinct examples of the attack class '{class}'. Each example
is a realistic tool response body that contains the attack. Vary phrasing, length, and framing. Do not
repeat earlier examples. Output strict JSONL with fields text and label."

Per-class targets: bring every underrepresented class up to a floor of 2,000 train examples; cap the
augmentation at 10x the source count for that class. Overall augmented working set expected in the 300k
to 340k range.

Rejection filters applied to every generated row:
- Deduplicate against existing rows by BLAKE3.
- Length bounds: 16 to 8,000 characters.
- Coherence check: a second cheap model pass or heuristic rejects degenerate or empty outputs.
- Label consistency: reject rows a quick Layer 2a/2b pass classifies as clearly the wrong class.

### §4.4 FAISS index build

- Embedding model: all-MiniLM-L6-v2, 384 dimensions, cosine similarity (normalize embeddings).
- Index type: `IndexHNSWFlat`. Parameters: `M=32`, `efConstruction=200`, `efSearch=64`.
- Source vectors: all malicious-class training rows (not benign), embedded post-canonicalization.
- On-disk format: `data/processed/faiss.index` plus a metadata sidecar `data/processed/faiss_meta.jsonl`
  with `{ vector_id, label, source, blake3, text_preview }` aligned to index ids.
- Rebuild is deterministic given the processed train split and the seed.

### §4.5 DeBERTa fine-tuning

- Base model: `microsoft/deberta-v3-base`; matching tokenizer.
- Task: sequence classification over the 18-class taxonomy plus benign (19 labels).
- Sequence length: 512. Batch size: 16 (gradient accumulation to effective 32 on CPU/limited GPU).
- Learning rate: 2e-5; optimizer AdamW; linear scheduler with 6% warmup.
- Epochs: 3 (early-stop on val macro-F1). Loss: cross-entropy with class weights for imbalance.
- Eval metric: macro-F1 and per-class recall on the val split; final report on test.
- Saved to `workers/layer4_judges/models/deberta-trishul/`; version and metrics logged to the data card.

---

## §5 Frontend Specification

### §5.1 API contract

Backend: FastAPI. Base path `/api`. WebSocket at `/ws/traffic`.

| Method | Path | Request | Response |
|--------|------|---------|----------|
| GET | /api/health | none | `{ status, components: {...} }` |
| GET | /api/stats/summary | none | `{ total_calls, blocked, escalated, allowed, fp_rate }` |
| GET | /api/traffic/recent | `?limit` | `list[TrafficRow]` |
| GET | /api/attacks | none | `list[AttackDef]` (the 18) |
| POST | /api/attacks/{id}/fire | `{ target_tool? }` | `AttackResult` (verdict + per-layer trace) |
| GET | /api/attacks/report | none | aggregated report JSON (testing.md §7) |
| GET | /api/audit/verify | none | `{ intact: bool, first_break: int? }` |
| GET | /api/system/layers | none | `list[LayerStatus]` (up/down, P95) |

WebSocket `/ws/traffic` messages: `TrafficEvent { invocation_id, tool_name, decision, layer_trace:
list[{layer_id, decision, latency_ms}], timestamp }` streamed live; `LayerHealth` heartbeat every 5 s.

`TrafficRow`, `AttackDef`, `AttackResult`, `LayerStatus` schemas are defined in
`backend/schemas.py` and mirror §2.1 where applicable.

### §5.2 Page inventory

Sidebar order: Dashboard, Live Traffic, Attack Simulator, Attack Workflow, Analysis, System, Settings.

| Page | Purpose | Data (API) | Components | Interaction states |
|------|---------|-----------|-----------|--------------------|
| Dashboard | At-a-glance posture | /api/stats/summary, /api/system/layers | StatCards, verdict donut, layer health strip | loading, live, error |
| Live Traffic | Real-time stream of verdicts | /ws/traffic, /api/traffic/recent | streaming table, verdict chips, filter bar | connected, paused, filtered |
| Attack Simulator | Fire any of the 18 attacks on demand | /api/attacks, POST fire | attack picker, fire button, live verdict panel | idle, firing, blocked, leaked |
| Attack Workflow | Animated replay of a triggered attack through the layers | AttackResult trace | animated pipeline diagram, layer cards, timeline scrubber | replaying, paused, step |
| Analysis | Benchmarks and reports | /api/attacks/report | coverage matrix, latency charts, FP gauge | loading, ready |
| System | Component health and audit integrity | /api/system/layers, /api/audit/verify | health grid, audit-chain status | ok, degraded, tampered |
| Settings | Theme, thresholds view, judge toggles | local + config read | theme toggle, config viewer | light, dark |

The two required tabs are Attack Simulator (fire + live decision) and Attack Workflow (animated flow).

### §5.3 Design system

- Tailwind config at `frontend/tailwind.config.ts`. Design tokens as CSS variables in
  `frontend/src/styles/tokens.css`.
- Accent: emerald (primary action and ALLOW). Semantic: emerald=allow, red=block, amber=escalate.
- Typography: Inter for UI, JetBrains Mono for code and identifiers. Scale: 12/14/16/20/24/32.
- Spacing scale: 4px base (4, 8, 12, 16, 24, 32, 48). Radius: 8px cards, 6px controls.
- Elevation: three shadow steps (sm, md, lg) defined once as tokens; cards use md.
- Layout: card-based, matching the reference dashboards to be shared separately.

### §5.4 Theme system

- Light and dark implemented with CSS variables plus the Tailwind `dark:` prefix; a `data-theme`
  attribute on `<html>` drives the variable set.
- Persistence: the chosen theme is stored in `localStorage` and restored on load; default follows the
  OS `prefers-color-scheme`.
- Contrast: every token pair is checked for WCAG AA (4.5:1 text, 3:1 large text) in both themes; the
  check is part of the frontend test pass (testing.md references the frontend build in §5).

---

## §6 Mock MCP Server Specification

### §6.1 Tool inventory

The mock server exposes deliberately weak tools so every attack can be staged locally with no real
third-party service. All returned secrets, PII, URLs, and numbers are synthetic.

| Tool | Description | Input schema | Response schema |
|------|-------------|--------------|-----------------|
| fs.read_file | Read a file from a fake repo | `{ path }` | `{ content: str }` |
| fs.search | Search fake documents | `{ query }` | `{ hits: [{ path, snippet }] }` |
| web.fetch | Fetch a fake web page | `{ url }` | `{ title, body }` |
| chat.send | Send a message (fake) | `{ to, body }` | `{ sent: bool }` |
| img.screenshot | Return a generated image | `{ subject }` | `{ image: MediaPart }` |
| audio.note | Return a generated voice note | `{ subject }` | `{ audio: MediaPart }` |
| repo.manifest | Return a tool manifest (mutable) | `{ tool }` | `{ manifest }` |
| logs.tail | Return fake logs (may contain secrets) | `{ service }` | `{ lines: [str] }` |

### §6.2 Attack payload catalog

Reference: `mock_server/payloads/attacks.json`. One entry per payload:

```json
{
  "id": "05",
  "class": "unicode_tag_smuggling",
  "target_tool": "fs.read_file",
  "request": { "path": "notes/roadmap.md" },
  "payload_ref": "payloads/raw/05_tag_smuggling.bin",
  "expected_block_layer": "1.5",
  "expected_reason": "unicode_tag_smuggling",
  "notes": "Instruction encoded in U+E00xx tag characters inside benign prose"
}
```

### §6.3 How each attack is triggered

Every attack maps to one tool call that returns the catalog payload. Expected block layers match the
Attack Coverage Matrix in the README.

| # | Class | Tool endpoint | Returns | Expected block layer |
|---|-------|---------------|---------|----------------------|
| 1 | tool_description_poisoning | repo.manifest | poisoned description | 5 (also 2a/4) |
| 2 | rugpull_redefinition | repo.manifest | redefined manifest after approval | 5 |
| 3 | indirect_prompt_injection | fs.read_file | body with injected instructions | 2a/2b/4 |
| 4 | data_exfiltration | fs.read_file | "send this to ..." instruction | 2a/4 |
| 5 | unicode_tag_smuggling | fs.read_file | tag-block encoded instruction | 1.5 |
| 6 | zero_width_obfuscation | fs.search | zero-width interleaved payload | 1.5 |
| 7 | homoglyph_substitution | web.fetch | homoglyph-substituted instruction | 1.5 (also 2b) |
| 8 | cross_call_split_payload | fs.search (x3) | payload fragments across calls | 3 |
| 9 | secret_credential_leak | logs.tail | seeded fake secrets | 2a (Judge D) |
| 10 | phishing_url_injection | web.fetch | phishing URL + visit instruction | 2a/2b |
| 11 | ocr_image_injection | img.screenshot | image with embedded text | 1 to 1.5 to 2a |
| 12 | audio_injection | audio.note | audio speaking an instruction | 1 (STT) to 2a |
| 13 | jailbreak_payload | fs.read_file | DAN-style payload | 2b/4 |
| 14 | schema_drift | repo.manifest | altered schema | 5 |
| 15 | confused_deputy_exfil | fs.read_file + chat.send | cross-tool exfil flow | 3/4 |
| 16 | denial_of_wallet | web.fetch (flood) | borderline content at high rate | 6 |
| 17 | command_code_injection | fs.read_file | shell one-liner + run instruction | 2a/4 |
| 18 | pii_harvesting | fs.search | seeded PII + harvest instruction | 2b/4 |
