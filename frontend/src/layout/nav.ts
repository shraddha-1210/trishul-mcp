import {
  Activity,
  BarChart3,
  Database,
  Gauge,
  type LucideIcon,
  Network,
  ScrollText,
  Settings,
  Swords,
  Timer,
} from "lucide-react"

export type LayerStatus = "live" | "designed"

export interface NavItem {
  label: string
  to: string
  icon: LucideIcon
}

export interface CapabilityItem {
  label: string
  to: string // /architecture#<anchor>
  status: LayerStatus
}

export const MAIN_NAV: NavItem[] = [
  { label: "Dashboard", to: "/", icon: Gauge },
  { label: "Attack Simulator", to: "/simulate", icon: Swords },
  { label: "Architecture", to: "/architecture", icon: Network },
]

// Layer 5 is built and live (rug-pull demo, Beat 5), so it is green here.
export const CAPABILITIES: CapabilityItem[] = [
  { label: "Layer 1.5 Normalize", to: "/architecture#layer-1-5", status: "live" },
  { label: "Layer 2a Patterns", to: "/architecture#layer-2a", status: "live" },
  { label: "Layer 4 Judge", to: "/architecture#layer-4", status: "live" },
  { label: "Layer 5 Schema Drift", to: "/architecture#layer-5", status: "live" },
  { label: "Layer 2b Semantic", to: "/architecture#layer-2b", status: "designed" },
  { label: "Layer 3 Aggregator", to: "/architecture#layer-3", status: "designed" },
  { label: "Layer 6 Anomaly", to: "/architecture#layer-6", status: "designed" },
]

export const SYSTEM_NAV: NavItem[] = [
  { label: "Audit Log", to: "/audit", icon: ScrollText },
  { label: "Data Pipeline", to: "/architecture#data-pipeline", icon: Database },
  { label: "Settings", to: "/settings", icon: Settings },
]

// Top-bar titles, including routes that are not in the sidebar.
export const PAGE_TITLES: Record<string, string> = {
  "/": "Dashboard",
  "/simulate": "Attack Simulator",
  "/architecture": "Architecture",
  "/audit": "Audit Log",
  "/settings": "Settings",
  "/workflow": "Attack Workflow",
  "/benchmarks": "Benchmarks",
  "/analytics": "Analytics",
}

// Placeholder routes: they exist so Architecture/Dashboard links have targets.
export const STUB_ROUTES: { path: string; icon: LucideIcon; blurb: string }[] = [
  { path: "/audit", icon: ScrollText, blurb: "Full, filterable history of every verdict." },
  { path: "/settings", icon: Settings, blurb: "Theme, thresholds and judge configuration." },
  { path: "/workflow", icon: Activity, blurb: "Step-through replay of an attack across the cascade." },
  { path: "/benchmarks", icon: Timer, blurb: "Detection and latency benchmarks per layer." },
  { path: "/analytics", icon: BarChart3, blurb: "Trends across tools, attack classes and layers." },
]
