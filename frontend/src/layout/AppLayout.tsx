import { useEffect } from "react"
import { Outlet, useLocation } from "react-router-dom"

import { Sidebar } from "./Sidebar"
import { TopBar } from "./TopBar"

// Scroll to #anchor on navigation (sidebar capability links), otherwise to the top.
function ScrollToHash() {
  const { pathname, hash } = useLocation()
  useEffect(() => {
    if (!hash) {
      window.scrollTo({ top: 0 })
      return
    }
    // Wait a frame so the target page has rendered its sections.
    const id = requestAnimationFrame(() => {
      document.getElementById(hash.slice(1))?.scrollIntoView({ behavior: "smooth", block: "start" })
    })
    return () => cancelAnimationFrame(id)
  }, [pathname, hash])
  return null
}

export function AppLayout() {
  return (
    <div className="flex min-h-screen">
      <ScrollToHash />
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="flex-1 px-8 py-8">
          <div className="mx-auto w-full max-w-[1280px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
