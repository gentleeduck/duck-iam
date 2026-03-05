import { ArrowRightIcon } from 'lucide-react'
import Link from 'next/link'

export function Announcement() {
  return (
    <Link
      className="mx-auto inline-flex items-center gap-2 rounded-full border bg-muted px-3 py-1 text-sm hover:bg-muted/80"
      href="/docs">
        <span className="rounded-full bg-primary/10 px-2 py-0.5 font-medium text-primary text-xs">New</span>
        <span className="text-sm">
          duck-iam is production-ready <span className="underline">Get started</span>
        </span>
        <ArrowRightIcon />
    </Link>
  )
}
