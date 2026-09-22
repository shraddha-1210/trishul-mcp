import { motion } from "framer-motion"
import { Loader2, Zap } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { ATTACK_ICONS, SEVERITY_CLASS, toolLabel } from "@/lib/attackMeta"
import { cn } from "@/lib/utils"
import type { AttackInfo } from "@/lib/types"

export function AttackCard({
  attack,
  firing,
  disabled,
  onFire,
}: {
  attack: AttackInfo
  firing: boolean
  disabled: boolean
  onFire: () => void
}) {
  const Icon = ATTACK_ICONS[attack.id] ?? Zap
  return (
    <motion.div
      animate={firing ? { scale: [1, 1.012, 1] } : { scale: 1 }}
      transition={firing ? { duration: 1.1, repeat: Infinity, ease: "easeInOut" } : { duration: 0.2 }}
    >
      <Card
        className={cn(
          "gap-3 px-5 py-5 shadow-md transition-all duration-200",
          "hover:-translate-y-0.5 hover:ring-brand/40 hover:shadow-lg",
          firing && "ring-2 ring-brand/70",
        )}
      >
        <div className="flex items-start gap-3">
          <div
            className={cn(
              "flex size-9 shrink-0 items-center justify-center rounded-lg",
              attack.severity === "medium" ? "bg-amber-soft text-amber" : "bg-block-soft text-block",
            )}
          >
            <Icon className="size-4.5" strokeWidth={1.75} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <h3 className="truncate text-sm font-semibold">{attack.name}</h3>
              <span
                className={cn(
                  "shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium capitalize",
                  SEVERITY_CLASS[attack.severity] ?? "bg-surface-2 text-muted-foreground",
                )}
              >
                {attack.severity}
              </span>
            </div>
            <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{attack.tool_name}</p>
          </div>
        </div>

        <p className="text-[13px] leading-relaxed text-muted-foreground">{attack.description}</p>

        <div className="flex items-center justify-between pt-1">
          <span className="text-[11px] text-muted-foreground">
            Live call to the {toolLabel(attack.tool_name)} MCP tool
          </span>
          <Button size="sm" onClick={onFire} disabled={disabled} data-testid={`fire-${attack.id}`}>
            {firing ? <Loader2 className="animate-spin" /> : <Zap />}
            {firing ? "Firing" : "Fire Attack"}
          </Button>
        </div>
      </Card>
    </motion.div>
  )
}
