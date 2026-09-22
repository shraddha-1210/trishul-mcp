import { Route, Routes } from "react-router-dom"

import { PAGE_TITLES, STUB_ROUTES } from "@/layout/nav"
import { AppLayout } from "@/layout/AppLayout"
import { ArchitecturePage } from "@/pages/ArchitecturePage"
import { ComingSoonPage } from "@/pages/ComingSoonPage"
import { DashboardPage } from "@/pages/DashboardPage"
import { SimulatorPage } from "@/pages/SimulatorPage"
import { FileQuestion } from "lucide-react"

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="simulate" element={<SimulatorPage />} />
        <Route path="architecture" element={<ArchitecturePage />} />
        {STUB_ROUTES.map(({ path, icon, blurb }) => (
          <Route
            key={path}
            path={path.slice(1)}
            element={<ComingSoonPage title={PAGE_TITLES[path]} icon={icon} blurb={blurb} />}
          />
        ))}
        <Route
          path="*"
          element={<ComingSoonPage title="Page not found" icon={FileQuestion} blurb="This route does not exist." />}
        />
      </Route>
    </Routes>
  )
}
