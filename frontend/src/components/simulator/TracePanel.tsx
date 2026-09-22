import { AnimatePresence, motion } from "framer-motion"
import { ChevronRight, MinusCircle } from "lucide-react"
import { useState } from "react"

import { LAYER_NAMES } from "@/lib/attackMeta"
import type { LayerResult } from "@/lib/types"
import { cn } from "@/lib/utils"
import { LAYER_IDS, type RunState } from "@/stores/verdicts"

const MAX_SNIPPET = 320

/** Invisible attack characters (tag block, zero width, bidi) shown as a visible marker. */
function isInvisible(cp: number) {
  return (
    (cp >= 0x200b && cp <= 0x200f) || // zero width space .. RTL mark
    (cp >= 0x2028 && cp <= 0x202e) || // line/paragraph separators, bidi overrides
    (cp >= 0x2060 && cp <= 0x2064) || // word joiner .. invisible plus
    cp === 0xfeff || // BOM
    (cp >= 0xe0000 && cp <= 0xe007f) // Unicode tag block (Attack 1)
  )
}

function visualize(text: string) {
  return Array.from(text, (ch) => (isInvisible(ch.codePointAt(0)!) ? "·" : ch)).join("")
}

function Snippet({ label, text }: { label: string; text: string }) {
  const [expanded, setExpanded] = useState(false)
  if (!text) return null
  const long = text.length > MAX_SNIPPET
  const shown = expanded || !long ? text : text.slice(0, MAX_SNIPPET)
  return (
    <div className="min-w-0">
      <div className="mb-1 flex items-center gap-2">
        <span className="text-[11px] font-medium tracking-wide text-muted-foreground uppercase">{label}</span>
        <span className="font-mono text-[10px] text-muted-foreground">{text.length} chars</span>
        {long && (
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="text-[11px] font-medium text-brand-text hover:underline"
          >
            {expanded ? "collapse" : "expand"}
          </button>
        )}
      </div>
      <pre className="overflow-x-auto rounded-lg bg-surface-2 p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap">
        {visualize(shown)}
        {long && !expanded && <span className="text-muted-foreground"> …</span>}
      </pre>
    </div>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2 text-[12px]">
      <span className="shrink-0 text-muted-foreground">{label}</span>
      <span className="font-mono break-all">{value}</span>
    </div>
  )
}

function LayerDetails({ layer }: { layer: LayerResult }) {
  const d = layer.details as Record<string, never>
  if (layer.layer === "5") {
    const changes = (d.changes ?? []) as { summary: string }[]
    const approved = d.approved_manifest as { description?: string } | null
    const live = d.live_manifest as { description?: string } | null
    return (
      <div className="flex flex-col gap-2">
        {changes.length > 0 && (
          <div className="flex flex-col gap-1">
            <span className="text-[11px] font-medium tracking-wide text-muted-foreground uppercase">
              Manifest changes since approval
            </span>
            {changes.map((c) => (
              <div key={c.summary} className="rounded-lg bg-block-soft px-3 py-1.5 font-mono text-[11px] text-block">
                {c.summary}
              </div>
            ))}
          </div>
        )}
        {approved?.description && live?.description && (
          <div className="grid gap-2 md:grid-cols-2">
            <Snippet label="Approved description" text={approved.description} />
            <Snippet label="Live description" text={live.description} />
          </div>
        )}
        <Detail label="approved" value={String(d.approved_at ?? "—")} />
      </div>
    )
  }
  if (layer.layer === "1.5") {
    const types = (d.stripped_types ?? []) as string[]
    return (
      <div className="flex flex-col gap-1.5">
        {types.length > 0 && <Detail label="stripped" value={types.join(", ")} />}
        {Boolean(d.stripped_chars_count) && (
          <Detail label="invisible chars" value={String(d.stripped_chars_count)} />
        )}
        {Boolean(d.homoglyph_count) && <Detail label="homoglyphs folded" value={String(d.homoglyph_count)} />}
        {Boolean(d.hidden_text) && (
          <Snippet label="Hidden instruction revealed" text={String(d.hidden_text)} />
        )}
      </div>
    )
  }
  if (layer.layer === "2a") {
    const patterns = (d.matched_patterns ?? []) as string[]
    const categories = (d.categories ?? []) as string[]
    if (!patterns.length) return null
    return (
      <div className="flex flex-col gap-1.5">
        <div className="flex flex-wrap gap-1.5">
          {patterns.map((p) => (
            <span key={p} className="rounded-md bg-block-soft px-2 py-0.5 font-mono text-[11px] text-block">
              {p}
            </span>
          ))}
        </div>
        {categories.length > 0 && <Detail label="categories" value={categories.join(", ")} />}
      </div>
    )
  }
  if (layer.layer === "4") {
    return (
      <div className="flex flex-col gap-1.5">
        <Detail label="model" value={String(d.model ?? "")} />
        {d.confidence !== undefined && d.confidence !== null && (
          <Detail label="confidence" value={String(d.confidence)} />
        )}
        {Boolean(d.error) && <Detail label="error" value={String(d.error)} />}
      </div>
    )
  }
  return null
}

function TraceRow({ layer }: { layer: LayerResult }) {
  const [open, setOpen] = useState(false)
  const blocked = layer.verdict === "BLOCK"
  return (
    <div className="border-b last:border-b-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        data-testid={`trace-row-${layer.layer}`}
        className="flex w-full items-center gap-3 px-1 py-3 text-left transition-colors hover:bg-surface-2/60"
      >
        <ChevronRight
          className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")}
        />
        <span className="w-24 shrink-0 font-mono text-xs">Layer {layer.layer}</span>
        <span className="w-24 shrink-0 text-xs text-muted-foreground">{layer.name}</span>
        <span
          className={cn(
            "shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium",
            blocked ? "bg-block-soft text-block" : "bg-allow-soft text-allow",
          )}
        >
          {layer.verdict}
        </span>
        <span className="min-w-0 flex-1 truncate text-[12px] text-muted-foreground">{layer.reasoning}</span>
        <span className="shrink-0 font-mono text-[11px] text-muted-foreground tabular-nums">
          {layer.latency_ms < 1 ? layer.latency_ms.toFixed(2) : Math.round(layer.latency_ms)} ms
        </span>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: "easeInOut" }}
            className="overflow-hidden"
          >
            <div className="flex flex-col gap-3 px-8 pt-1 pb-4">
              {layer.layer === "4" && layer.reasoning && (
                <p className="rounded-lg bg-surface-2 px-3 py-2 font-mono text-[12px] italic">
                  “{layer.reasoning}”
                </p>
              )}
              <LayerDetails layer={layer} />
              {layer.layer !== "5" && (
                <div className="grid gap-3 md:grid-cols-2">
                  <Snippet label="Input" text={layer.input_text} />
                  <Snippet label="Output" text={layer.output_text} />
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function SkippedRow({ layerId, reason }: { layerId: string; reason?: string }) {
  return (
    <div className="flex items-center gap-3 border-b px-1 py-3 last:border-b-0 opacity-55">
      <MinusCircle className="size-4 shrink-0 text-muted-foreground" />
      <span className="w-24 shrink-0 font-mono text-xs">Layer {layerId}</span>
      <span className="w-24 shrink-0 text-xs text-muted-foreground">{LAYER_NAMES[layerId]}</span>
      <span className="shrink-0 rounded-full bg-surface-2 px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
        SKIPPED
      </span>
      <span className="min-w-0 flex-1 truncate text-[12px] text-muted-foreground">{reason}</span>
    </div>
  )
}

export function TracePanel({ run }: { run: RunState }) {
  const trace = run.result?.trace ?? []
  const ran = new Set(trace.map((l) => l.layer))
  return (
    <div className="rounded-2xl border px-5 py-2">
      {LAYER_IDS.map((id) => {
        const layer = trace.find((l) => l.layer === id)
        if (layer) return <TraceRow key={id} layer={layer} />
        if (ran.size === 0) return null
        return <SkippedRow key={id} layerId={id} reason={run.layers[id]?.skipReason} />
      })}
    </div>
  )
}
