import { AlertTriangle, HelpCircle, type LucideIcon, RefreshCcw, ShieldAlert } from "lucide-react"

/** Per-attack presentation. Content (name, description, severity) comes from GET /api/attacks. */
export const ATTACK_ICONS: Record<string, LucideIcon> = {
  unicode_tag_credential_exfil: AlertTriangle,
  homoglyph_injection: ShieldAlert,
  novel_encoding_rot13: HelpCircle,
  rug_pull_calendar: RefreshCcw,
}

export const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-block-soft text-block",
  high: "bg-block-soft text-block",
  medium: "bg-amber-soft text-amber",
}

export const LAYER_NAMES: Record<string, string> = {
  "5": "Schema Drift",
  "1.5": "Normalize",
  "2a": "Patterns",
  "4": "Judge",
}

/** Human label for the tool each attack rides in on. */
export function toolLabel(toolName: string): string {
  return toolName.split(".")[0]
}
