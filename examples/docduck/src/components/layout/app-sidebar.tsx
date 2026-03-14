'use client'

import { Avatar, AvatarFallback } from '@gentleduck/ui/avatar'

import { Separator } from '@gentleduck/ui/separator'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@gentleduck/ui/tooltip'
import { useAtom } from 'jotai'
import { FileTextIcon, FolderIcon, SettingsIcon } from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { sidebarOpenAtom } from '@/lib/atoms'
import type { Session } from '@/lib/auth'

interface NavItemProps {
  href: string
  icon: React.ReactNode
  label: string
  active: boolean
  collapsed: boolean
}

function NavItem({ href, icon, label, active, collapsed }: NavItemProps) {
  const link = (
    <Link
      href={href}
      className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors ${
        active
          ? 'bg-primary/10 font-medium text-primary'
          : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
      } ${collapsed ? 'justify-center px-2' : ''}`}>
      {icon}
      {!collapsed && <span>{label}</span>}
    </Link>
  )

  if (collapsed) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>{link}</TooltipTrigger>
        <TooltipContent side="right">{label}</TooltipContent>
      </Tooltip>
    )
  }

  return link
}

interface AppSidebarProps {
  user: Session['user']
}

export function AppSidebar({ user }: AppSidebarProps) {
  const [open] = useAtom(sidebarOpenAtom)
  const pathname = usePathname()

  const workspaceMatch = pathname.match(/\/workspaces\/([^/]+)/)
  const currentSlug = workspaceMatch?.[1]

  const collapsed = !open

  return (
    <TooltipProvider delayDuration={0}>
      <aside
        className={`flex h-full flex-col border-r bg-muted/30 transition-all duration-200 ${open ? 'w-64' : 'w-14'}`}>
        {/* Logo */}
        <div className="flex h-14 items-center gap-2.5 border-b px-4">
          <FileTextIcon className="h-5 w-5 shrink-0 text-primary" />
          {!collapsed && <span className="font-semibold tracking-tight">DocDuck</span>}
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-1 p-2">
          <NavItem
            href="/workspaces"
            icon={<FolderIcon className="h-4 w-4 shrink-0" />}
            label="Workspaces"
            active={pathname === '/workspaces'}
            collapsed={collapsed}
          />

          {currentSlug && (
            <>
              <Separator className="my-3" />
              {!collapsed && (
                <div className="mb-2 flex items-center gap-2 px-3">
                  <span className="font-medium text-muted-foreground text-xs uppercase">Workspace</span>
                </div>
              )}
              <NavItem
                href={`/workspaces/${currentSlug}`}
                icon={<FileTextIcon className="h-4 w-4 shrink-0" />}
                label="Documents"
                active={pathname.startsWith(`/workspaces/${currentSlug}`) && !pathname.includes('/settings')}
                collapsed={collapsed}
              />
              <NavItem
                href={`/workspaces/${currentSlug}/settings`}
                icon={<SettingsIcon className="h-4 w-4 shrink-0" />}
                label="Settings"
                active={pathname.startsWith(`/workspaces/${currentSlug}/settings`)}
                collapsed={collapsed}
              />
            </>
          )}
        </nav>

        {/* User section at bottom */}
        <Separator />
        <div className="p-2">
          <div className={`flex items-center gap-2.5 rounded-lg px-2 py-2 ${collapsed ? 'justify-center' : ''}`}>
            <Avatar className="h-8 w-8 shrink-0">
              <AvatarFallback className="bg-primary font-medium text-primary-foreground text-xs">
                {user.name?.charAt(0)?.toUpperCase() ?? '?'}
              </AvatarFallback>
            </Avatar>
            {!collapsed && (
              <div className="flex-1 overflow-hidden">
                <p className="truncate font-medium text-sm leading-tight">{user.name}</p>
                <p className="truncate text-muted-foreground text-xs">{user.email}</p>
              </div>
            )}
          </div>
        </div>
      </aside>
    </TooltipProvider>
  )
}
