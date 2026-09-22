import { AnimatePresence, motion } from "framer-motion"
import { ChevronRight } from "lucide-react"
import { useEffect, useState } from "react"

import { CascadeDiagram, DiagramLegend } from "@/components/architecture/CascadeDiagram"
import { PageHeader } from "@/components/PageHeader"
import { StatusBadge } from "@/components/StatusBadge"
import { Card } from "@/components/ui/card"
import { DATA_PIPELINE } from "@/data/dataPipeline"
import { LAYER_DOCS, type LayerDoc } from "@/data/layers"
import { SEED_CLASSES } from "@/data/seedSamples"
import { API_URL } from "@/lib/api"
import type { Metrics } from "@/lib/types"
import { cn } from "@/lib/utils"
import { useMetricsStore } from "@/stores/metrics"

function Contract({ text }: { text: string }) {
  return (
    <pre className="overflow-x-auto rounded-lg bg-surface-2 px-3 py-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap">
      {text}
    </pre>
  )
}

function LiveStats({ doc, metrics }: { doc: LayerDoc; metrics: Metrics | null }) {
  const stats = doc.statsKey ? metrics?.per_layer_stats[doc.statsKey] : undefined
  const cells: [string, string][] = [
    ["Responses inspected", stats ? String(stats.inspected) : "—"],
    ["Blocks", stats ? String(stats.blocks) : "—"],
    ["Avg latency", stats ? `${stats.avg_latency_ms.toFixed(2)} ms` : "—"],
  ]
  return (
    <div className="grid grid-cols-3 gap-3 rounded-xl border p-3">
      {cells.map(([label, value]) => (
        <div key={label}>
          <div className="text-[11px] text-muted-foreground">{label}</div>
          <div className="font-mono text-sm tabular-nums">{value}</div>
        </div>
      ))}
    </div>
  )
}

function LayerSection({ doc, metrics }: { doc: LayerDoc; metrics: Metrics | null }) {
  return (
    <Card id={doc.anchor} className="scroll-mt-20 gap-4 px-6 py-5 shadow-md">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-base font-semibold tracking-tight">{doc.title}</h2>
        <StatusBadge status={doc.status} />
      </div>
      <p className="text-[13px] leading-relaxed text-muted-foreground">{doc.purpose}</p>
      <Contract text={doc.contract} />
      <p className="text-[13px]">
        <span className="text-muted-foreground">Tool: </span>
        <span className="font-medium">{doc.tool}</span>
        <span className="text-muted-foreground"> — {doc.toolWhy}</span>
      </p>
      {doc.status === "live" && <LiveStats doc={doc} metrics={metrics} />}
      {doc.status === "designed" && (
        <div className="rounded-xl border border-amber/25 bg-amber-soft px-4 py-3">
          <p className="text-[13px] font-medium text-amber">
            Specced in implementation.md, awaiting integration. {doc.estimate}
          </p>
          {doc.excerpt && (
            <pre className="mt-2 overflow-x-auto font-mono text-[11px] leading-relaxed whitespace-pre-wrap text-foreground/75">
              {doc.excerpt}
            </pre>
          )}
        </div>
      )}
      {doc.note && <p className="text-[12px] text-muted-foreground">{doc.note}</p>}
    </Card>
  )
}

function StatCard({ value, label, detail }: { value: string; label: string; detail: string }) {
  return (
    <div className="rounded-xl border p-4">
      <div className="font-mono text-xl font-semibold tabular-nums">{value}</div>
      <div className="mt-1 text-[13px] font-medium">{label}</div>
      <div className="mt-0.5 text-[11px] leading-relaxed text-muted-foreground">{detail}</div>
    </div>
  )
}

function SeedAccordion() {
  const [open, setOpen] = useState<string | null>(null)
  return (
    <div className="rounded-xl border">
      {SEED_CLASSES.map((cls) => (
        <div key={cls.id} className="border-b last:border-b-0">
          <button
            type="button"
            onClick={() => setOpen((v) => (v === cls.id ? null : cls.id))}
            data-testid={`seed-${cls.id}`}
            className="flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-surface-2/60"
          >
            <ChevronRight
              className={cn(
                "size-4 shrink-0 text-muted-foreground transition-transform",
                open === cls.id && "rotate-90",
              )}
            />
            <span className="flex-1 text-[13px] font-medium">{cls.title}</span>
            <span className="font-mono text-[11px] text-muted-foreground">{cls.count} seeds</span>
          </button>
          <AnimatePresence initial={false}>
            {open === cls.id && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2, ease: "easeInOut" }}
                className="overflow-hidden"
              >
                <div className="flex flex-col gap-2 px-11 pb-3">
                  {cls.samples.map((s, i) => (
                    <pre
                      key={i}
                      className="overflow-x-auto rounded-lg bg-surface-2 px-3 py-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap"
                    >
                      {s}
                    </pre>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      ))}
    </div>
  )
}

export function ArchitecturePage() {
  const { metrics, setMetrics } = useMetricsStore()

  useEffect(() => {
    fetch(`${API_URL}/api/metrics`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then(setMetrics)
      .catch(() => {
        // Live stats fall back to em dashes; the rest of the page is static.
      })
  }, [setMetrics])

  const d = DATA_PIPELINE
  const sources = Object.entries(d.publicSources)
    .map(([name, n]) => `${name} ${n}`)
    .join(", ")

  return (
    <>
      <PageHeader
        title="System Architecture"
        subtitle="Four layers running, three designed and specced, two enterprise scope."
      />

      <Card className="gap-4 px-6 py-6 shadow-md">
        <span className="text-sm font-medium">Cascade</span>
        <CascadeDiagram />
        <DiagramLegend />
      </Card>

      <div className="mt-6 flex flex-col gap-4">
        {LAYER_DOCS.map((doc) => (
          <LayerSection key={doc.anchor} doc={doc} metrics={metrics} />
        ))}

        <Card id="data-pipeline" className="scroll-mt-20 gap-4 px-6 py-5 shadow-md">
          <div>
            <h2 className="text-base font-semibold tracking-tight">Training Data Pipeline</h2>
            <p className="mt-1 text-[13px] text-muted-foreground">
              Ground truth for the detection models. Every number below is counted from the files in
              the repository.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
            <StatCard
              value={String(d.seedTotal)}
              label="Hand-written attack seeds"
              detail={`${d.seedClasses} classes x 25 seeds, written by hand`}
            />
            <StatCard
              value={d.publicRows.toLocaleString()}
              label="Public dataset rows"
              detail={sources}
            />
            <StatCard
              value={String(d.generatedRows)}
              label="Deterministic generator variants"
              detail={`${d.generatedClasses} classes, including ${d.pngCount} PNG OCR and ${d.wavCount} WAV audio artifacts`}
            />
            <StatCard
              value={String(d.llmRows)}
              label="LLM-generated synthetic, kept"
              detail={`${d.llmClasses} classes; mass generation stopped when Layer 2b left demo scope`}
            />
          </div>

          <p className="text-[12px] text-muted-foreground">
            Processed splits: {d.splits.train_real.toLocaleString()} train / {d.splits.val} val /{" "}
            {d.splits.test} test. OWASP MCP Top 10 is reference-only (zero training rows),
            MCP-SafetyBench is reserved for attack-coverage validation, and WildJailbreak is still
            gated, so neither contributes rows.
          </p>

          <div>
            <p className="mb-2 text-[13px] font-medium">Sample seed viewer</p>
            <SeedAccordion />
          </div>
        </Card>
      </div>
    </>
  )
}
