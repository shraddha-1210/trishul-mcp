import { useCallback, useEffect, useState } from "react"
import { Link } from "react-router-dom"

import { TrafficChart } from "@/components/dashboard/TrafficChart"
import { PageHeader } from "@/components/PageHeader"
import { Card } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useCountUp } from "@/hooks/useCountUp"
import { API_URL } from "@/lib/api"
import { LAYER_NAMES } from "@/lib/attackMeta"
import type { AuditPage, AuditRow, Metrics } from "@/lib/types"
import { cn } from "@/lib/utils"
import { useMetricsStore } from "@/stores/metrics"

const REFRESH_MS = 5000
const HEALTH_LAYERS = ["1.5", "2a", "4", "5"]

function relativeTime(iso: string) {
  const diff = Date.now() - Date.parse(iso)
  const mins = Math.round(diff / 60_000)
  if (mins < 1) return "just now"
  if (mins < 60) return `${mins}m ago`
  const hours = Math.round(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.round(hours / 24)}d ago`
}

function MetricCard({
  label,
  value,
  format,
  accent,
}: {
  label: string
  value: number | null
  format: (n: number) => string
  accent?: string
}) {
  const shown = useCountUp(value ?? 0)
  return (
    <Card className="gap-3 px-6 py-5 shadow-md">
      <span className="text-sm text-muted-foreground">{label}</span>
      {value === null ? (
        <Skeleton className="h-8 w-24" />
      ) : (
        <span className={cn("font-mono text-2xl font-semibold tabular-nums", accent)}>
          {format(shown)}
        </span>
      )}
    </Card>
  )
}

export function DashboardPage() {
  const { metrics, recentAudit, setMetrics, setRecentAudit } = useMetricsStore()
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const [m, a] = await Promise.all([
        fetch(`${API_URL}/api/metrics`).then((r) => r.json() as Promise<Metrics>),
        fetch(`${API_URL}/api/audit?limit=200`).then((r) => r.json() as Promise<AuditPage>),
      ])
      setMetrics(m)
      setRecentAudit(a.items)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [setMetrics, setRecentAudit])

  useEffect(() => {
    load()
    const id = setInterval(load, REFRESH_MS)
    return () => clearInterval(id)
  }, [load])

  const blocks: AuditRow[] = recentAudit.filter((r) => r.decision === "BLOCK").slice(0, 10)

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle="Real-time MCP tool response inspection"
        actions={
          error ? (
            <span className="text-xs text-block">backend unreachable: {error}</span>
          ) : (
            <span className="text-xs text-muted-foreground">refreshing every 5s</span>
          )
        }
      />

      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <MetricCard label="Total Requests" value={metrics?.total_requests ?? null} format={(n) => Math.round(n).toString()} />
        <MetricCard
          label="Attacks Blocked"
          value={metrics?.blocks ?? null}
          format={(n) => Math.round(n).toString()}
          accent="text-allow"
        />
        <MetricCard
          label="Attack Success Rate"
          value={metrics ? metrics.attack_success_rate * 100 : null}
          format={(n) => `${n.toFixed(1)}%`}
          accent={metrics && metrics.attack_success_rate > 0 ? "text-block" : "text-allow"}
        />
        <MetricCard
          label="Avg Latency"
          value={metrics?.avg_latency_ms ?? null}
          format={(n) => `${Math.round(n)} ms`}
        />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="gap-4 px-6 py-5 shadow-md xl:col-span-2">
          <div className="flex items-baseline justify-between">
            <span className="text-sm font-medium">Live traffic</span>
            <span className="text-xs text-muted-foreground">last 60 minutes</span>
          </div>
          <TrafficChart rows={recentAudit} />
        </Card>

        <Card className="gap-4 px-6 py-5 shadow-md">
          <span className="text-sm font-medium">Layer health</span>
          <div className="grid flex-1 grid-cols-2 gap-3">
            {HEALTH_LAYERS.map((id) => {
              const stats = metrics?.per_layer_stats[id]
              return (
                <div key={id} className="flex flex-col justify-between rounded-xl border p-3">
                  <div>
                    <div className="text-[13px] font-medium">Layer {id}</div>
                    <div className="text-[11px] text-muted-foreground">{LAYER_NAMES[id]}</div>
                  </div>
                  <div className="mt-3 flex items-center gap-1.5">
                    <span className="size-1.5 animate-pulse rounded-full bg-allow shadow-[0_0_0_3px_var(--allow-soft)]" />
                    <span className="text-[11px] text-allow">Live</span>
                    <span className="ml-auto font-mono text-[11px] text-muted-foreground tabular-nums">
                      {stats ? `${stats.avg_latency_ms.toFixed(1)} ms` : "—"}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </Card>
      </div>

      <Card className="mt-4 gap-3 px-6 py-5 shadow-md">
        <div className="flex items-baseline justify-between">
          <span className="text-sm font-medium">Recent Blocked Attacks</span>
          <Link to="/audit" className="text-xs font-medium text-brand-text hover:underline">
            View all
          </Link>
        </div>
        <table className="w-full text-left text-[13px]">
          <thead>
            <tr className="text-[11px] tracking-wide text-muted-foreground uppercase">
              <th className="py-2 font-medium">Time</th>
              <th className="py-2 font-medium">Attack</th>
              <th className="py-2 font-medium">Layer caught</th>
              <th className="py-2 text-right font-medium">Latency</th>
              <th className="py-2 text-right font-medium">Verdict</th>
            </tr>
          </thead>
          <tbody>
            {blocks.length === 0 && (
              <tr>
                <td colSpan={5} className="py-6 text-center text-muted-foreground">
                  No blocks recorded yet
                </td>
              </tr>
            )}
            {blocks.map((row) => (
              <tr key={row.id} className="border-t transition-colors hover:bg-surface-2/60">
                <td className="py-2.5 text-muted-foreground">{relativeTime(row.timestamp)}</td>
                <td className="py-2.5 font-mono text-[12px]">{row.attack_id}</td>
                <td className="py-2.5">
                  {row.blocked_at_layer ? `Layer ${row.blocked_at_layer}` : "—"}
                  <span className="ml-1.5 text-[11px] text-muted-foreground">
                    {row.blocked_at_layer ? LAYER_NAMES[row.blocked_at_layer] : ""}
                  </span>
                </td>
                <td className="py-2.5 text-right font-mono tabular-nums">
                  {Math.round(row.total_latency_ms)} ms
                </td>
                <td className="py-2.5 text-right">
                  <span className="rounded-full bg-block-soft px-2 py-0.5 text-[11px] font-medium text-block">
                    {row.decision}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  )
}
