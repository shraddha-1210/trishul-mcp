import mermaid from "mermaid"
import { useEffect, useId, useRef, useState } from "react"

import { useThemeStore } from "@/stores/theme"

/** Emerald = built and running, amber = designed, blue = enterprise scope. */
const GRAPH = `flowchart LR
  agent([AI Agent])
  tool[/MCP Tool Server/]
  l5[Layer 5\\nSchema Drift]
  l15[Layer 1.5\\nNormalize]
  l2a[Layer 2a\\nPatterns]
  l2b[Layer 2b\\nSemantic]
  l3[Layer 3\\nAggregator]
  l4[Layer 4\\nAI Judge]
  l6[Layer 6\\nAnomaly]
  policy[Policy Engine]
  audit[(Audit Log)]
  cap[Capability Layer\\n30s scoped tokens]
  hmac[Audit HMAC Chain]

  agent -- tool call --> l5
  l5 -- manifest ok --> tool
  tool -- response --> l15
  l15 --> l2a
  l2a --> l4
  l2a -.-> l2b
  l2b -.-> l3
  l3 -.-> policy
  l4 --> policy
  l5 -- drift = BLOCK --> policy
  l6 -.-> policy
  policy --> audit
  policy -- ALLOW --> delivered([Response reaches the agent])
  cap -.-> tool
  audit -.-> hmac

  classDef live fill:#10b981,stroke:#065f46,color:#022c22
  classDef designed fill:#f59e0b,stroke:#92400e,color:#1c1206
  classDef enterprise fill:#3b82f6,stroke:#1e40af,color:#f8fafc
  classDef plain fill:transparent,stroke:#71717a
  class l15,l2a,l4,l5,policy,audit live
  class l2b,l3,l6 designed
  class cap,hmac enterprise
  class agent,tool,delivered plain
`

export function CascadeDiagram() {
  const theme = useThemeStore((s) => s.theme)
  const containerRef = useRef<HTMLDivElement>(null)
  const [error, setError] = useState<string | null>(null)
  const id = useId().replace(/:/g, "")

  useEffect(() => {
    let cancelled = false
    mermaid.initialize({
      startOnLoad: false,
      theme: theme === "dark" ? "dark" : "default",
      fontFamily: "Inter, sans-serif",
      themeVariables: { background: "transparent", lineColor: theme === "dark" ? "#6e6e6e" : "#a1a1a1" },
      flowchart: { curve: "basis", padding: 12 },
    })
    mermaid
      .render(`cascade-${id}`, GRAPH)
      .then(({ svg }) => {
        if (cancelled || !containerRef.current) return
        containerRef.current.innerHTML = svg
        const el = containerRef.current.querySelector("svg")
        if (el) {
          el.removeAttribute("height")
          el.style.maxWidth = "100%"
        }
      })
      .catch((e: Error) => !cancelled && setError(e.message))
    return () => {
      cancelled = true
    }
  }, [theme, id])

  if (error) return <p className="text-sm text-block">Diagram failed to render: {error}</p>
  return <div ref={containerRef} data-testid="cascade-diagram" className="w-full overflow-x-auto" />
}

export function DiagramLegend() {
  const items: [string, string, string][] = [
    ["bg-allow", "Running", "built, tested, in the demo"],
    ["bg-amber-dot", "Designed", "specced, next milestone"],
    ["bg-enterprise", "Enterprise scope", "production deployment"],
  ]
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-t pt-4">
      {items.map(([dot, label, note]) => (
        <span key={label} className="flex items-center gap-2 text-xs">
          <span className={`size-2.5 rounded-sm ${dot}`} />
          <span className="font-medium">{label}</span>
          <span className="text-muted-foreground">{note}</span>
        </span>
      ))}
    </div>
  )
}
