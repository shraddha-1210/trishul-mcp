import type { LucideIcon } from "lucide-react"
import { Link } from "react-router-dom"

import { PageHeader } from "@/components/PageHeader"
import { Card } from "@/components/ui/card"

export function ComingSoonPage({ title, icon: Icon, blurb }: { title: string; icon: LucideIcon; blurb: string }) {
  return (
    <>
      <PageHeader title={title} />
      <Card className="items-center gap-3 px-6 py-20 text-center shadow-md">
        <div className="flex size-11 items-center justify-center rounded-xl bg-surface-2 text-muted-foreground">
          <Icon className="size-5" strokeWidth={1.75} />
        </div>
        <p className="text-base font-medium">Coming soon in the next milestone</p>
        <p className="max-w-sm text-sm text-muted-foreground">{blurb}</p>
        <Link to="/architecture" className="mt-2 text-sm font-medium text-brand-text hover:underline">
          See the architecture →
        </Link>
      </Card>
    </>
  )
}
