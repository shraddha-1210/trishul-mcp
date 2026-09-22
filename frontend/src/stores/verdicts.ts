import { create } from "zustand"

import type { SimulateResponse } from "@/lib/types"

export type NodeState = "idle" | "running" | "allow" | "block" | "skipped" | "done"

export interface LayerLive {
  state: NodeState
  latencyMs?: number
  reasoning?: string
  skipReason?: string
}

/** One simulation run, assembled live from /ws/live events plus the final POST body. */
export interface RunState {
  runId: string | null
  attackId: string
  layers: Record<string, LayerLive>
  toolCall: { state: NodeState; latencyMs?: number }
  result: SimulateResponse | null
  error: string | null
}

export const LAYER_IDS = ["5", "1.5", "2a", "4"] as const

function freshRun(attackId: string): RunState {
  return {
    runId: null,
    attackId,
    layers: Object.fromEntries(LAYER_IDS.map((id) => [id, { state: "idle" as NodeState }])),
    toolCall: { state: "idle" },
    result: null,
    error: null,
  }
}

interface VerdictsState {
  firing: boolean
  run: RunState | null
  connected: boolean
  startRun: (attackId: string) => void
  applyEvent: (event: Record<string, unknown>) => void
  finishRun: (result: SimulateResponse) => void
  failRun: (message: string) => void
  setConnected: (connected: boolean) => void
}

export const useVerdictsStore = create<VerdictsState>((set, get) => ({
  firing: false,
  run: null,
  connected: false,

  startRun: (attackId) => set({ firing: true, run: freshRun(attackId) }),

  applyEvent: (event) => {
    const run = get().run
    if (!run) return
    // Events from an older run (or another browser tab) must not move this one.
    if (run.runId && event.run_id && event.run_id !== run.runId) return
    const layer = event.layer as string | undefined
    const next: RunState = { ...run, layers: { ...run.layers } }
    if (event.run_id && !next.runId) next.runId = event.run_id as string

    switch (event.event) {
      case "tool_call":
        next.toolCall = { state: "done", latencyMs: event.latency_ms as number }
        break
      case "layer_start":
        if (layer) next.layers[layer] = { ...next.layers[layer], state: "running" }
        break
      case "layer_complete":
        if (layer)
          next.layers[layer] = {
            state: event.verdict === "BLOCK" ? "block" : "allow",
            latencyMs: event.latency_ms as number,
            reasoning: event.reasoning as string,
          }
        break
      case "layer_skipped":
        if (layer)
          next.layers[layer] = { state: "skipped", skipReason: event.reason as string }
        // A skipped response layer means the call was never forwarded.
        if (next.toolCall.state === "idle") next.toolCall = { state: "skipped" }
        break
      case "run_error":
        next.error = String(event.error)
        break
      default:
        break // "verdict" is applied from the POST response, which carries the full trace
    }
    set({ run: next })
  },

  finishRun: (result) => {
    const run = get().run
    set({ firing: false, run: run ? { ...run, result } : run })
  },

  failRun: (message) => {
    const run = get().run
    set({ firing: false, run: run ? { ...run, error: message } : run })
  },

  setConnected: (connected) => set({ connected }),
}))
