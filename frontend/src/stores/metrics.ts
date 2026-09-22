import { create } from "zustand"
import type { AuditRow, Metrics } from "@/lib/types"

// Shell: filled from GET /api/metrics and /api/audit in Step 10.
interface MetricsState {
  metrics: Metrics | null
  recentAudit: AuditRow[]
  setMetrics: (metrics: Metrics) => void
  setRecentAudit: (rows: AuditRow[]) => void
}

export const useMetricsStore = create<MetricsState>((set) => ({
  metrics: null,
  recentAudit: [],
  setMetrics: (metrics) => set({ metrics }),
  setRecentAudit: (recentAudit) => set({ recentAudit }),
}))
