import { motion } from "framer-motion"
import { CheckCircle2, ShieldX } from "lucide-react"

import { LAYER_NAMES } from "@/lib/attackMeta"
import type { SimulateResponse } from "@/lib/types"
import { cn } from "@/lib/utils"

function ms(value: number) {
  return value < 1 ? `${value.toFixed(2)} ms` : `${Math.round(value)} ms`
}

export function VerdictBanner({ result }: { result: SimulateResponse }) {
  const blocked = result.final_verdict === "BLOCK"
  const layer = result.blocked_at_layer
  const title = blocked
    ? layer
      ? `BLOCKED at Layer ${layer} — ${LAYER_NAMES[layer] ?? ""}`
      : "BLOCKED"
    : "ALLOWED"
  const Icon = blocked ? ShieldX : CheckCircle2

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      data-testid="verdict-banner"
      data-verdict={result.final_verdict}
      className={cn(
        "rounded-2xl border px-6 py-5",
        blocked ? "border-block/30 bg-block-soft" : "border-allow/30 bg-allow-soft",
      )}
    >
      <div className="flex items-start gap-3">
        <Icon className={cn("mt-0.5 size-5 shrink-0", blocked ? "text-block" : "text-allow")} strokeWidth={2} />
        <div className="min-w-0 flex-1">
          <h3 className={cn("text-base font-semibold", blocked ? "text-block" : "text-allow")}>{title}</h3>
          <p className="mt-1 text-[13px] leading-relaxed text-foreground/80">{result.reason}</p>
          <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 font-mono text-[11px] text-muted-foreground tabular-nums">
            <span>
              Trishul <span className="text-foreground">{ms(result.total_latency_ms)}</span>
            </span>
            {result.mcp_latency_ms !== null && (
              <span>
                MCP round trip <span className="text-foreground">{ms(result.mcp_latency_ms)}</span>
              </span>
            )}
            <span>
              call forwarded{" "}
              <span className={result.forwarded ? "text-foreground" : "text-block"}>
                {result.forwarded ? "yes" : "no"}
              </span>
            </span>
            <span>
              audit #<span className="text-foreground">{result.audit_id}</span>
            </span>
          </div>
        </div>
      </div>
    </motion.div>
  )
}
