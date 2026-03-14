'use client'

import { useAtom } from 'jotai'
import { FileTextIcon, FolderIcon, SettingsIcon } from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Card } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
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
      className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] transition-all duration-150 ${
        active
          ? 'bg-primary/10 font-semibold text-primary shadow-sm'
          : 'text-muted-foreground hover:translate-x-0.5 hover:bg-accent/80 hover:text-foreground'
      } ${collapsed ? 'justify-center px-2' : ''}`}>
      <span className={`shrink-0 transition-transform duration-150 ${active ? 'scale-110' : ''}`}>{icon}</span>
      {!collapsed && <span className="truncate">{label}</span>}
    </Link>
  )

  if (collapsed) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>{link}</TooltipTrigger>
        <TooltipContent side="right" className="font-medium">
          {label}
        </TooltipContent>
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
        className={`flex h-full flex-col border-r bg-muted/20 transition-all duration-200 ${open ? 'w-64' : 'w-14'}`}>
        {/* Accent gradient line */}
        <div className="h-0.5 w-full bg-gradient-to-r from-primary via-primary/60 to-transparent" />

        {/* Logo */}
        <div className="flex h-14 items-center gap-2.5 border-b px-4">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10">
            <FileTextIcon className="h-4 w-4 text-primary" />
          </div>
          {!collapsed && <span className="font-bold text-[15px] tracking-tight">DocDuck</span>}
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-1 p-2">
          {!collapsed && (
            <p className="mb-2 px-3 pt-2 font-semibold text-[11px] text-muted-foreground/70 uppercase tracking-wider">
              General
            </p>
          )}
          <NavItem
            href="/workspaces"
            icon={<FolderIcon className="h-4 w-4" />}
            label="Workspaces"
            active={pathname === '/workspaces'}
            collapsed={collapsed}
          />

          {currentSlug && (
            <>
              <Separator className="my-3" />
              {!collapsed && (
                <p className="mb-2 px-3 pt-1 font-semibold text-[11px] text-muted-foreground/70 uppercase tracking-wider">
                  Workspace
                </p>
              )}
              <NavItem
                href={`/workspaces/${currentSlug}`}
                icon={<FileTextIcon className="h-4 w-4" />}
                label="Documents"
                active={pathname.startsWith(`/workspaces/${currentSlug}`) && !pathname.includes('/settings')}
                collapsed={collapsed}
              />
              <NavItem
                href={`/workspaces/${currentSlug}/settings`}
                icon={<SettingsIcon className="h-4 w-4" />}
                label="Settings"
                active={pathname.startsWith(`/workspaces/${currentSlug}/settings`)}
                collapsed={collapsed}
              />
            </>
          )}
        </nav>

        {/* User section */}
        <div className="p-2">
          <Card className={`border-border/50 bg-muted/40 shadow-none ${collapsed ? 'p-2' : 'p-3'}`}>
            <div className={`flex items-center gap-2.5 ${collapsed ? 'justify-center' : ''}`}>
              <Avatar className="h-8 w-8 shrink-0 ring-2 ring-primary/20 ring-offset-1 ring-offset-background">
                <AvatarFallback className="bg-gradient-to-br from-primary to-primary/70 font-semibold text-primary-foreground text-xs">
                  {user.name?.charAt(0)?.toUpperCase() ?? '?'}
                </AvatarFallback>
              </Avatar>
              {!collapsed && (
                <div className="flex-1 overflow-hidden">
                  <p className="truncate font-semibold text-[13px] leading-tight">{user.name}</p>
                  <p className="truncate text-[11px] text-muted-foreground">{user.email}</p>
                </div>
              )}
            </div>
          </Card>
        </div>
      </aside>
    </TooltipProvider>
  )
}
