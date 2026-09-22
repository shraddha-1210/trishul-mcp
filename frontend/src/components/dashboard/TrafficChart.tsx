import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"

import type { AuditRow } from "@/lib/types"
import { useThemeStore } from "@/stores/theme"

/** Bucket the audit rows into the last 60 one-minute slots. */
export function bucketByMinute(rows: AuditRow[], now = Date.now(), minutes = 60) {
  const start = now - (minutes - 1) * 60_000
  const buckets = Array.from({ length: minutes }, (_, i) => ({
    t: start + i * 60_000,
    requests: 0,
    blocks: 0,
  }))
  for (const row of rows) {
    const ts = Date.parse(row.timestamp)
    if (Number.isNaN(ts)) continue
    const idx = Math.floor((ts - start) / 60_000)
    if (idx < 0 || idx >= minutes) continue
    buckets[idx].requests += 1
    if (row.decision === "BLOCK") buckets[idx].blocks += 1
  }
  return buckets.map((b) => ({
    ...b,
    label: new Date(b.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  }))
}

export function TrafficChart({ rows }: { rows: AuditRow[] }) {
  const theme = useThemeStore((s) => s.theme)
  const data = bucketByMinute(rows)
  const axis = theme === "dark" ? "#6e6e6e" : "#8a8a94"
  const grid = theme === "dark" ? "#1f1f1f" : "#e6e6e9"

  return (
    <ResponsiveContainer width="100%" height={224}>
      <AreaChart data={data} margin={{ top: 4, right: 8, left: -24, bottom: 0 }}>
        <defs>
          <linearGradient id="traffic" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#10b981" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#10b981" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={grid} vertical={false} />
        <XAxis
          dataKey="label"
          interval={11}
          tick={{ fill: axis, fontSize: 11 }}
          tickLine={false}
          axisLine={{ stroke: grid }}
        />
        <YAxis
          allowDecimals={false}
          width={44}
          tick={{ fill: axis, fontSize: 11 }}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip
          contentStyle={{
            background: "var(--surface)",
            border: "1px solid var(--border)",
            borderRadius: 12,
            fontSize: 12,
          }}
          labelStyle={{ color: "var(--muted-foreground)" }}
        />
        <Area
          type="monotone"
          dataKey="requests"
          stroke="#10b981"
          strokeWidth={2}
          fill="url(#traffic)"
          isAnimationActive={false}
          name="requests"
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
