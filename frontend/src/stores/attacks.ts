import { create } from "zustand"
import type { AttackInfo } from "@/lib/types"

// Shell: populated from GET /api/attacks in Step 8.
interface AttacksState {
  attacks: AttackInfo[]
  setAttacks: (attacks: AttackInfo[]) => void
}

export const useAttacksStore = create<AttacksState>((set) => ({
  attacks: [],
  setAttacks: (attacks) => set({ attacks }),
}))
