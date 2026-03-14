'use client'

import { useAtom } from 'jotai'
import { FileTextIcon, FolderIcon, SettingsIcon } from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { sidebarOpenAtom } from '@/lib/atoms'
import type { Session } from '@/lib/auth'

interface AppSidebarProps {
  user: Session['user']
}

export function AppSidebar({ user }: AppSidebarProps) {
  const [open, _setOpen] = useAtom(sidebarOpenAtom)
  const pathname = usePathname()

  // Extract workspace slug from URL if present
  const workspaceMatch = pathname.match(/\/workspaces\/([^/]+)/)
  const currentSlug = workspaceMatch?.[1]

  return (
    <aside
      className={`flex h-full flex-col border-r bg-muted/50 transition-all duration-200 ${
        open ? 'w-64' : 'w-0 overflow-hidden'
      }`}>
      <div className="flex h-14 items-center gap-2 border-b px-4">
        <FileTextIcon className="h-5 w-5" />
        <span className="font-semibold">DocDuck</span>
      </div>

      <nav className="flex-1 space-y-1 p-3">
        <Link
          href="/workspaces"
          className={`flex items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-accent ${
            pathname === '/workspaces' ? 'bg-accent font-medium' : ''
          }`}>
          <FolderIcon className="h-4 w-4" />
          Workspaces
        </Link>

        {currentSlug && (
          <>
            <div className="mt-4 mb-2 px-3 font-medium text-muted-foreground text-xs uppercase">Workspace</div>
            <Link
              href={`/workspaces/${currentSlug}`}
              className={`flex items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-accent ${
                pathname === `/workspaces/${currentSlug}` ? 'bg-accent font-medium' : ''
              }`}>
              <FileTextIcon className="h-4 w-4" />
              Documents
            </Link>
            <Link
              href={`/workspaces/${currentSlug}/settings`}
              className={`flex items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-accent ${
                pathname.includes('/settings') ? 'bg-accent font-medium' : ''
              }`}>
              <SettingsIcon className="h-4 w-4" />
              Settings
            </Link>
          </>
        )}
      </nav>

      <div className="border-t p-3">
        <div className="flex items-center gap-2 px-3 py-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary font-medium text-primary-foreground text-xs">
            {user.name?.charAt(0)?.toUpperCase() ?? '?'}
          </div>
          <div className="flex-1 truncate text-sm">{user.name}</div>
        </div>
      </div>
    </aside>
  )
}
