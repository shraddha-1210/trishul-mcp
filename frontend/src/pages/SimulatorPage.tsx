import { useEffect, useState } from "react"
import { toast } from "sonner"

import { PageHeader } from "@/components/PageHeader"
import { AttackCard } from "@/components/simulator/AttackCard"
import { Pipeline } from "@/components/simulator/Pipeline"
import { TracePanel } from "@/components/simulator/TracePanel"
import { VerdictBanner } from "@/components/simulator/VerdictBanner"
import { Card } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useLiveSocket } from "@/hooks/useLiveSocket"
import { API_URL } from "@/lib/api"
import type { AttackInfo, SimulateResponse } from "@/lib/types"
import { cn } from "@/lib/utils"
import { useAttacksStore } from "@/stores/attacks"
import { useVerdictsStore } from "@/stores/verdicts"

function ConnectionDot({ connected }: { connected: boolean }) {
  return (
    <span className="flex items-center gap-2 text-xs text-muted-foreground">
      <span
        className={cn(
          "size-1.5 rounded-full",
          connected ? "bg-allow shadow-[0_0_0_3px_var(--allow-soft)]" : "bg-block",
        )}
      />
      {connected ? "live feed connected" : "live feed offline"}
    </span>
  )
}

export function SimulatorPage() {
  useLiveSocket()
  const { attacks, setAttacks } = useAttacksStore()
  const { firing, run, connected, startRun, finishRun, failRun } = useVerdictsStore()
  const [loadError, setLoadError] = useState<string | null>(null)

  useEffect(() => {
    if (attacks.length) return
    fetch(`${API_URL}/api/attacks`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((data: AttackInfo[]) => setAttacks(data))
      .catch((e: Error) => setLoadError(e.message))
  }, [attacks.length, setAttacks])

  async function fire(attack: AttackInfo) {
    startRun(attack.id)
    try {
      const res = await fetch(`${API_URL}/api/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_id: attack.id }),
      })
      if (!res.ok) {
        const body = await res.text()
        throw new Error(`HTTP ${res.status}: ${body.slice(0, 200)}`)
      }
      const result: SimulateResponse = await res.json()
      finishRun(result)
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      failRun(message)
      // Keep the pipeline state on screen; the toast explains what broke.
      toast.error("Simulation failed", { description: message })
    }
  }

  return (
    <>
      <PageHeader
        title="Attack Simulator"
        subtitle="Fire a real attack at a live MCP tool and watch every layer inspect it."
        actions={<ConnectionDot connected={connected} />}
      />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[2fr_3fr]">
        <div className="flex flex-col gap-3">
          {loadError && (
            <Card className="gap-1 px-5 py-4 text-sm shadow-md">
              <span className="font-medium text-block">Could not load attacks</span>
              <span className="text-muted-foreground">
                {loadError} — is the backend running on {API_URL}?
              </span>
            </Card>
          )}
          {!attacks.length && !loadError
            ? Array.from({ length: 4 }, (_, i) => (
                <Card key={i} className="gap-3 px-5 py-5 shadow-md">
                  <Skeleton className="h-9 w-full" />
                  <Skeleton className="h-3.5 w-3/4" />
                </Card>
              ))
            : attacks.map((attack) => (
                <AttackCard
                  key={attack.id}
                  attack={attack}
                  firing={firing && run?.attackId === attack.id}
                  disabled={firing}
                  onFire={() => fire(attack)}
                />
              ))}
        </div>

        <div className="flex flex-col gap-4">
          <Card className="gap-6 px-6 py-6 shadow-md">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Pipeline</span>
              {run && (
                <span className="font-mono text-[11px] text-muted-foreground">
                  {run.runId ? `run ${run.runId}` : "starting…"}
                </span>
              )}
            </div>
            <Pipeline run={run} />
          </Card>

          {run?.result ? (
            <>
              <VerdictBanner result={run.result} />
              <TracePanel run={run} />
            </>
          ) : (
            <Card className="items-center justify-center px-6 py-14 text-sm text-muted-foreground shadow-md">
              {firing ? "Inspecting…" : "Fire an attack to see the verdict"}
            </Card>
          )}
        </div>
      </div>
    </>
  )
}
