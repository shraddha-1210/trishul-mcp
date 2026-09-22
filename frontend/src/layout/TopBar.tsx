import { Moon, Sun } from "lucide-react"
import { useLocation } from "react-router-dom"

import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useThemeStore } from "@/stores/theme"
import { PAGE_TITLES } from "./nav"

export function TopBar() {
  const { pathname } = useLocation()
  const theme = useThemeStore((s) => s.theme)
  const toggle = useThemeStore((s) => s.toggle)
  const next = theme === "dark" ? "light" : "dark"

  return (
    <header className="sticky top-0 z-20 flex h-(--topbar-height) items-center justify-between border-b bg-background/80 px-8 backdrop-blur-md">
      <div className="flex items-center gap-2 text-sm">
        <span className="text-muted-foreground">Trishul</span>
        <span className="text-muted-foreground/50">/</span>
        <span className="font-medium">{PAGE_TITLES[pathname] ?? "Not found"}</span>
      </div>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            onClick={toggle}
            aria-label={`Switch to ${next} theme`}
            data-testid="theme-toggle"
            className="text-muted-foreground hover:text-foreground"
          >
            {theme === "dark" ? <Sun strokeWidth={1.75} /> : <Moon strokeWidth={1.75} />}
          </Button>
        </TooltipTrigger>
        <TooltipContent>Switch to {next} theme</TooltipContent>
      </Tooltip>
    </header>
  )
}
