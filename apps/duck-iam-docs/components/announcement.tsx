<<<<<<< HEAD:apps/duck-iam-docs/components/announcement.tsx
=======
import { Badge } from '@gentleduck/registry-ui/badge'
>>>>>>> 68028f2b8f071c10853ff31e15c817d8fd06f964:apps/duck-gen-docs/components/announcement.tsx
import { ArrowRightIcon } from 'lucide-react'
import Link from 'next/link'

export function Announcement() {
  return (
<<<<<<< HEAD:apps/duck-iam-docs/components/announcement.tsx
    <Link
      className="mx-auto inline-flex items-center gap-2 rounded-full border bg-muted px-3 py-1 text-sm hover:bg-muted/80"
      href="/docs">
        <span className="rounded-full bg-primary/10 px-2 py-0.5 font-medium text-primary text-xs">New</span>
        <span className="text-sm">
          duck-iam is production-ready <span className="underline">Get started</span>
        </span>
        <ArrowRightIcon />
=======
    <Badge asChild className="mx-auto max-w-full rounded-full" variant="secondary">
      <Link className="flex items-center gap-2 overflow-hidden" href="/docs/duck-gen">
        <span className="shrink-0 rounded-full bg-primary/10 px-2 py-0.5 font-medium text-primary text-xs">New</span>
        <span className="truncate text-sm">Duck Gen and Duck Query are production-ready</span>
        <span className="hidden shrink-0 text-sm underline sm:inline">Get started</span>
        <ArrowRightIcon aria-hidden="true" className="shrink-0" />
>>>>>>> 68028f2b8f071c10853ff31e15c817d8fd06f964:apps/duck-gen-docs/components/announcement.tsx
      </Link>
  )
}
