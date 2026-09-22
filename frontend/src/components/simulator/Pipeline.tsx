import { AnimatePresence, motion } from "framer-motion"
import {
  Bot,
  Brain,
  FileSearch,
  Fingerprint,
  type LucideIcon,
  ScanLine,
  ShieldCheck,
  Wrench,
} from "lucide-react"

import { cn } from "@/lib/utils"
import type { NodeState, RunState } from "@/stores/verdicts"

/**
 * Request-side first: the manifest is checked (Layer 5) before the call is
 * forwarded, so the tool sits *after* L5. A Layer 5 block means the tool node and
 * every response layer are skipped, which is the Attack 4 story.
 */
interface NodeDef {
  key: string
  label: string
  sub?: string
  icon: LucideIcon
}

const NODES: NodeDef[] = [
  { key: "agent", label: "Agent", icon: Bot },
  { key: "layer:5", label: "L5", sub: "Schema", icon: Fingerprint },
  { key: "tool", label: "Tool", icon: Wrench },
  { key: "layer:1.5", label: "L1.5", sub: "Normalize", icon: ScanLine },
  { key: "layer:2a", label: "L2a", sub: "Patterns", icon: FileSearch },
  { key: "layer:4", label: "L4", sub: "Judge", icon: Brain },
  { key: "verdict", label: "Verdict", icon: ShieldCheck },
]

const RING: Record<NodeState, string> = {
  idle: "border-border-strong text-muted-foreground",
  running: "border-brand text-brand-text",
  allow: "border-allow text-allow bg-allow-soft",
  block: "border-block text-block bg-block-soft",
  skipped: "border-dashed border-border text-muted-foreground/50",
  done: "border-brand text-brand-text bg-brand-soft",
}

function nodeState(def: NodeDef, run: RunState | null): { state: NodeState; latency?: number } {
  if (!run) return { state: "idle" }
  if (def.key === "agent") return { state: "done" }
  if (def.key === "tool") return { state: run.toolCall.state, latency: run.toolCall.latencyMs }
  if (def.key === "verdict") {
    if (!run.result) return { state: "idle" }
    return { state: run.result.final_verdict === "BLOCK" ? "block" : "allow" }
  }
  const live = run.layers[def.key.slice(6)]
  return { state: live?.state ?? "idle", latency: live?.latencyMs }
}

function Connector({ active, done }: { active: boolean; done: boolean }) {
  return (
    <div className="relative mt-6 h-0.5 min-w-4 flex-1 overflow-hidden rounded-full bg-border">
      <motion.div
        className="absolute inset-y-0 left-0 bg-brand/70"
        initial={{ width: "0%" }}
        animate={{ width: done || active ? "100%" : "0%" }}
        transition={{ duration: 0.45, ease: "easeInOut" }}
      />
      <AnimatePresence>
        {active && (
          <motion.span
            className="absolute top-1/2 size-2 -translate-y-1/2 rounded-full bg-brand shadow-[0_0_8px_var(--accent-brand)]"
            initial={{ left: "0%" }}
            animate={{ left: "100%" }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.55, ease: "easeInOut" }}
          />
        )}
      </AnimatePresence>
    </div>
  )
}

export function Pipeline({ run }: { run: RunState | null }) {
  const states = NODES.map((n) => nodeState(n, run))

  return (
    <div className="flex items-start" data-testid="pipeline">
      {NODES.map((def, i) => {
        const { state, latency } = states[i]
        const Icon = def.icon
        const pulsing = state === "running"
        return (
          <div key={def.key} className="flex flex-1 items-start last:flex-none">
            <div className="flex w-[72px] shrink-0 flex-col items-center gap-1.5">
              <motion.div
                data-testid={`node-${def.key}`}
                data-state={state}
                animate={
                  pulsing
                    ? { scale: [1, 1.12, 1] }
                    : state === "allow" || state === "block"
                      ? { scale: [1.12, 1] }
                      : { scale: 1 }
                }
                transition={
                  pulsing
                    ? { duration: 1.2, repeat: Infinity, ease: "easeInOut" }
                    : { duration: 0.3, ease: "easeOut" }
                }
                className={cn(
                  "flex size-12 items-center justify-center rounded-full border-2 transition-colors duration-300",
                  RING[state],
                )}
              >
                <Icon className="size-5" strokeWidth={1.75} />
              </motion.div>
              <span
                className={cn(
                  "text-xs font-medium",
                  state === "skipped" ? "text-muted-foreground/50" : "text-foreground",
                )}
              >
                {def.label}
              </span>
              {def.sub && <span className="text-[10px] text-muted-foreground">{def.sub}</span>}
              <span className="h-4 font-mono text-[10px] text-muted-foreground tabular-nums">
                {state === "skipped"
                  ? "skipped"
                  : latency !== undefined
                    ? `${latency < 1 ? latency.toFixed(2) : Math.round(latency)} ms`
                    : ""}
              </span>
            </div>
            {i < NODES.length - 1 && (
              <Connector
                active={states[i + 1].state === "running"}
                done={["allow", "block", "done"].includes(states[i + 1].state)}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}
