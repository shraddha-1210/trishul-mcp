import type { BuildStatus } from "@/components/StatusBadge"

/**
 * Layer reference content. Purposes, contracts and spec excerpts are quoted from
 * docs/implementation.md §3; live numbers come from GET /api/metrics at render time.
 */
export interface LayerDoc {
  anchor: string
  title: string
  status: BuildStatus
  /** Key in Metrics.per_layer_stats; only set for layers that actually run. */
  statsKey?: string
  purpose: string
  contract: string
  tool: string
  toolWhy: string
  /** Designed layers only: verbatim excerpt from implementation.md. */
  excerpt?: string
  estimate?: string
  note?: string
}

export const LAYER_DOCS: LayerDoc[] = [
  {
    anchor: "layer-5",
    title: "Layer 5 — Schema Drift",
    status: "live",
    statsKey: "5",
    purpose:
      "Checks the tool manifest against the snapshot approved when the server was connected. Runs on the request side, before the call is forwarded, so a redefined tool never gets called.",
    contract: "check(tool_name, live_manifest) -> {verdict, status, changes[], live_hash, approved_hash}",
    tool: "SQLite snapshot store + BLAKE2b manifest hash",
    toolWhy: "an exact hash makes drift detection deterministic and sub-millisecond.",
  },
  {
    anchor: "layer-1-5",
    title: "Layer 1.5 — Normalize",
    status: "live",
    statsKey: "1.5",
    purpose:
      "Strips invisible Unicode, folds homoglyphs to Latin and decodes wrapped payloads, so every later layer reads one canonical form of the text.",
    contract:
      "normalize(text) -> {canonical_text, was_obfuscated, stripped_types[], stripped_chars_count, homoglyph_count, hidden_text}",
    tool: "Python unicodedata (NFKC) + a curated confusables table",
    toolWhy: "deterministic, no model, and fast enough to run on every response.",
  },
  {
    anchor: "layer-2a",
    title: "Layer 2a — Patterns",
    status: "live",
    statsKey: "2a",
    purpose:
      "Matches canonical text against a corpus of known-attack phrases and credential markers in a single pass.",
    contract: "scan(text) -> {matched, matched_patterns[], matched_spans[], categories[], latency_ms}",
    tool: "Aho-Corasick automaton (pyahocorasick)",
    toolWhy: "one pass over the text regardless of how many patterns are loaded.",
  },
  {
    anchor: "layer-4",
    title: "Layer 4 — AI Judge",
    status: "live",
    statsKey: "4",
    purpose:
      "Reads the response as a security reviewer would and rules on intent, catching attacks with no known pattern — the ROT13 case in this demo.",
    contract: 'judge(text, tool_name, tool_description) -> {verdict, confidence, reasoning, latency_ms}',
    tool: "Ollama running Llama 3.1 8B locally",
    toolWhy: "runs on the laptop with no API key and no data leaving the machine.",
    note: "Input is truncated to 6000 characters. A 15 s timeout fails closed to BLOCK.",
  },
  {
    anchor: "layer-2b",
    title: "Layer 2b — Semantic Similarity",
    status: "designed",
    purpose:
      "Catches paraphrased and previously unseen attacks by nearest-neighbour similarity against a known malicious corpus.",
    contract:
      'LayerVerdict layer_id="2b": BLOCK if top_score >= block_threshold, ESCALATE if above escalate_threshold, else PASS_THROUGH',
    tool: "FAISS HNSW index + all-MiniLM-L6-v2 embeddings",
    toolWhy: "sub-linear nearest-neighbour search over the attack corpus, entirely local.",
    excerpt:
      "**Purpose.** Catch paraphrased and previously unseen attacks by nearest-neighbor similarity to a known malicious corpus. Addresses classes 3, 7, 10, 13, 18 and any paraphrase that dodges Layer 2a.\n\n**Configuration.** config/layer2b.yaml: model (default \"all-MiniLM-L6-v2\"), index_path, block_threshold (default 0.85), escalate_threshold (default 0.70), top_k (default 5).",
    estimate: "Index build and threshold calibration: ~2 days.",
  },
  {
    anchor: "layer-3",
    title: "Layer 3 — Cross-Call Aggregator",
    status: "designed",
    purpose:
      "Detects payloads deliberately split across several responses in one session, where each fragment looks benign on its own.",
    contract:
      "{session_id, canonical_text, per_response_verdicts[]} -> LayerVerdict layer_id=\"3\" with reassembled_score and contributing_response_ids",
    tool: "Encrypted per-session ring buffer (AES-GCM) + re-scan of the reassembled text",
    toolWhy: "the buffer holds attacker-controlled text, so it is encrypted at rest and TTL-bound.",
    excerpt:
      "**Purpose.** Detect payloads deliberately split across multiple responses in a session that each look benign in isolation. Addresses classes 8 (split payload) and 15 (confused-deputy cross-server).\n\n**Configuration.** config/layer3.yaml: window_size (default 8 responses), ttl_seconds (default 300), reassembly_threshold (default 0.85).",
    estimate: "Session buffer, reassembly and tests: ~3 days.",
  },
  {
    anchor: "layer-6",
    title: "Layer 6 — Rate and Anomaly",
    status: "designed",
    purpose:
      "Spots denial-of-wallet floods and abnormal call patterns that try to burn the judge budget or probe the pipeline.",
    contract:
      "{server_id, session_id, latency_ms, decision, timestamp} -> LayerVerdict layer_id=\"6\" with anomaly_score",
    tool: "Rolling call-rate features + IsolationForest",
    toolWhy: "unsupervised, so it needs no labelled flood traffic to be useful on day one.",
    excerpt:
      "**Purpose.** Detect denial-of-wallet floods and abnormal call patterns that try to burn the judge budget or probe the pipeline. Addresses class 16 (denial-of-wallet).\n\n**Configuration.** config/layer6.yaml: window_seconds (default 60), contamination (default 0.02), escalation_rate_cap (default 20 per minute per session).",
    estimate: "Feature window, model and rate caps: ~2 days.",
  },
  {
    anchor: "capability-layer",
    title: "Capability Layer",
    status: "enterprise",
    purpose:
      "Bounds blast radius with short-lived, narrowly scoped tokens the agent must present per call, so a payload that evades every detector still cannot perform an out-of-scope action.",
    contract: "{invocation_id, requested_scope[], ttl_seconds} -> signed Ed25519 JWT + ValidationResult",
    tool: "PyJWT (Ed25519); SPIFFE/SPIRE in enterprise deployment",
    toolWhy: "binds a token to one invocation and one scope, with a 30-second default TTL.",
    note: "Reserved for production deployment. See the enterprise docker-compose overlay for HA, HSM and SPIFFE integration.",
  },
  {
    anchor: "audit-hmac",
    title: "Audit HMAC Chain",
    status: "enterprise",
    purpose:
      "Makes the audit log tamper-evident: every entry carries an HMAC over its body plus the previous entry's HMAC, so any edit breaks the chain.",
    contract: "verify() -> {intact: bool, first_break: int | null}",
    tool: "HMAC-SHA256 with an external signer",
    toolWhy: "detects tampering without needing a second database.",
    note: "Reserved for production deployment. The demo writes the same rows without the chain.",
  },
]
