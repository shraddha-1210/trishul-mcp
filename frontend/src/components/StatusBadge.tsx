import { cn } from "@/lib/utils"

export type BuildStatus = "live" | "designed" | "enterprise"

const STYLES: Record<BuildStatus, { label: string; className: string; dot: string }> = {
  live: { label: "Live", className: "bg-allow-soft text-allow", dot: "bg-allow" },
  designed: {
    label: "Designed — Next Milestone",
    className: "bg-amber-soft text-amber",
    dot: "bg-amber-dot",
  },
  enterprise: {
    label: "Enterprise Scope",
    className: "bg-enterprise-soft text-enterprise",
    dot: "bg-enterprise",
  },
}

export function StatusBadge({ status, className }: { status: BuildStatus; className?: string }) {
  const s = STYLES[status]
  return (
    <span
      className={cn(
        "inline-flex h-6 items-center gap-1.5 rounded-full px-2.5 text-xs font-medium",
        s.className,
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full", s.dot)} />
      {s.label}
    </span>
  )
}
