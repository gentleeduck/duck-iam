'use client'

import { Avatar, AvatarFallback } from '@gentleduck/ui/avatar'
import { Button } from '@gentleduck/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@gentleduck/ui/dropdown-menu'
import { Separator } from '@gentleduck/ui/separator'
import { useAtom } from 'jotai'
import { ChevronRightIcon, LogOutIcon, PanelLeftIcon } from 'lucide-react'
import { usePathname, useRouter } from 'next/navigation'
import { sidebarOpenAtom } from '@/lib/atoms'
import type { Session } from '@/lib/auth'
import { signOut } from '@/lib/auth-client'

interface TopbarProps {
  user: Session['user']
}

export function Topbar({ user }: TopbarProps) {
  const [sidebarOpen, setSidebarOpen] = useAtom(sidebarOpenAtom)
  const pathname = usePathname()
  const router = useRouter()

  const workspaceMatch = pathname.match(/\/workspaces\/([^/]+)/)
  const currentSlug = workspaceMatch?.[1]

  async function handleLogout() {
    await signOut()
    router.push('/auth/login')
    router.refresh()
  }

  return (
    <header className="flex h-14 items-center gap-3 border-b bg-background px-4">
      <Button
        type="button"
        variant="ghost"
        size="icon"
        onClick={() => setSidebarOpen(!sidebarOpen)}
        aria-label="Toggle sidebar"
        className="h-8 w-8">
        <PanelLeftIcon className="h-4 w-4" />
      </Button>

      <Separator orientation="vertical" className="h-5" />

      {/* Breadcrumb-style navigation */}
      <nav className="flex items-center gap-1.5 text-muted-foreground text-sm">
        <span>Workspaces</span>
        {currentSlug && (
          <>
            <ChevronRightIcon className="h-3.5 w-3.5" />
            <span className="font-medium text-foreground">{currentSlug}</span>
          </>
        )}
      </nav>

      <div className="flex-1" />

      {/* User dropdown */}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button type="button" variant="ghost" size="icon" className="h-8 w-8 rounded-full">
            <Avatar className="h-8 w-8">
              <AvatarFallback className="bg-primary font-medium text-primary-foreground text-xs">
                {user.name?.charAt(0)?.toUpperCase() ?? '?'}
              </AvatarFallback>
            </Avatar>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel className="font-normal">
            <div className="flex flex-col gap-1">
              <p className="font-medium text-sm leading-none">{user.name}</p>
              <p className="text-muted-foreground text-xs leading-none">{user.email}</p>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={handleLogout}>
            <LogOutIcon className="mr-2 h-4 w-4" />
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  )
}
