// Mirrors backend/schemas.py. Keep in sync when the API changes.

export type Verdict = "ALLOW" | "BLOCK"

export interface LayerResult {
  layer: string // "5" | "1.5" | "2a" | "4"
  name: string
  verdict: Verdict
  latency_ms: number
  input_text: string
  output_text: string
  reasoning: string | null
  details: Record<string, unknown>
}

export interface SimulateResponse {
  trace: LayerResult[]
  final_verdict: Verdict
  reason: string
  total_latency_ms: number
  blocked_at_layer: string | null
  attack_id: string
  tool_name: string
  timestamp: string
  audit_id: number
  source: "mcp" | "custom_text"
  forwarded: boolean
  mcp_latency_ms: number | null
}

export interface AttackInfo {
  id: string
  name: string
  description: string
  severity: "critical" | "high" | "medium" | string
  tool_name: string
  status: string
}

export interface AuditRow {
  id: number
  timestamp: string
  attack_id: string
  tool_name: string
  is_attack: boolean
  decision: string
  blocked_at_layer: string | null
  total_latency_ms: number
  reason: string
  seeded: boolean
}

export interface AuditPage {
  items: AuditRow[]
  total: number
  limit: number
  offset: number
}

export interface LayerStats {
  inspected: number
  blocks: number
  avg_latency_ms: number
}

export interface Metrics {
  total_requests: number
  blocks: number
  allows: number
  attack_success_rate: number
  avg_latency_ms: number
  per_layer_stats: Record<string, LayerStats>
}
