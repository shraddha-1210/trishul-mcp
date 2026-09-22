import { Link, NavLink, useLocation } from "react-router-dom"

import { Logo } from "@/components/brand/Logo"
import { cn } from "@/lib/utils"
import { CAPABILITIES, type LayerStatus, MAIN_NAV, type NavItem, SYSTEM_NAV } from "./nav"

const itemBase =
  "group flex h-8 items-center gap-2.5 rounded-lg px-2.5 text-sm transition-colors outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
const itemIdle = "text-muted-foreground hover:bg-surface-2 hover:text-foreground"
const itemActive = "bg-surface-2 font-medium text-foreground"

function SectionLabel({ children }: { children: string }) {
  return (
    <div className="px-2.5 pb-1.5 text-[11px] font-medium tracking-wider text-muted-foreground uppercase">
      {children}
    </div>
  )
}

export function StatusDot({ status }: { status: LayerStatus }) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "size-1.5 shrink-0 rounded-full",
        status === "live"
          ? "bg-allow shadow-[0_0_0_3px_var(--allow-soft)]"
          : "bg-amber-dot shadow-[0_0_0_3px_var(--amber-soft)]",
      )}
    />
  )
}

function useIsHashActive() {
  const { pathname, hash } = useLocation()
  return (to: string) => {
    const [path, anchor] = to.split("#")
    return pathname === path && hash === `#${anchor}`
  }
}

function RouteItem({ item }: { item: NavItem }) {
  const isHashActive = useIsHashActive()
  const Icon = item.icon
  const content = (
    <>
      <Icon className="size-4 shrink-0" strokeWidth={1.75} />
      <span className="truncate">{item.label}</span>
    </>
  )
  if (item.to.includes("#")) {
    return (
      <Link to={item.to} className={cn(itemBase, isHashActive(item.to) ? itemActive : itemIdle)}>
        {content}
      </Link>
    )
  }
  return (
    <NavLink
      to={item.to}
      end
      className={({ isActive }) => cn(itemBase, isActive ? itemActive : itemIdle)}
    >
      {content}
    </NavLink>
  )
}

export function Sidebar() {
  const isHashActive = useIsHashActive()
  const live = CAPABILITIES.filter((c) => c.status === "live").length
  const designed = CAPABILITIES.length - live

  return (
    <aside className="sticky top-0 flex h-screen w-(--sidebar-width) shrink-0 flex-col border-r bg-background">
      <div className="flex h-(--topbar-height) items-center px-5">
        <Link
          to="/"
          aria-label="Trishul home"
          className="rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
        >
          <Logo />
        </Link>
      </div>

      <nav className="flex flex-1 flex-col gap-6 overflow-y-auto px-3 pt-3 pb-6">
        <div>
          <SectionLabel>Main</SectionLabel>
          <div className="flex flex-col gap-0.5">
            {MAIN_NAV.map((item) => (
              <RouteItem key={item.to} item={item} />
            ))}
          </div>
        </div>

        <div>
          <SectionLabel>Capabilities</SectionLabel>
          <div className="flex flex-col gap-0.5">
            {CAPABILITIES.map((cap) => (
              <Link
                key={cap.to}
                to={cap.to}
                title={cap.status === "live" ? "Live" : "Designed, next milestone"}
                className={cn(itemBase, isHashActive(cap.to) ? itemActive : itemIdle)}
              >
                <span className="flex size-4 items-center justify-center">
                  <StatusDot status={cap.status} />
                </span>
                <span className="truncate">{cap.label}</span>
              </Link>
            ))}
          </div>
        </div>

        <div>
          <SectionLabel>System</SectionLabel>
          <div className="flex flex-col gap-0.5">
            {SYSTEM_NAV.map((item) => (
              <RouteItem key={item.to} item={item} />
            ))}
          </div>
        </div>
      </nav>

      <div className="flex items-center gap-2 border-t px-5 py-3.5 text-xs text-muted-foreground">
        <StatusDot status="live" />
        <span>{live} live</span>
        <span className="ml-2" />
        <StatusDot status="designed" />
        <span>{designed} designed</span>
      </div>
    </aside>
  )
}
