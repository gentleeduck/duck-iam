'use client'

import { useAtom } from 'jotai'
import { LogOutIcon, PanelLeftIcon } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { sidebarOpenAtom } from '@/lib/atoms'
import type { Session } from '@/lib/auth'
import { signOut } from '@/lib/auth-client'

interface TopbarProps {
  user: Session['user']
}

export function Topbar({ user }: TopbarProps) {
  const [sidebarOpen, setSidebarOpen] = useAtom(sidebarOpenAtom)
  const router = useRouter()

  async function handleLogout() {
    await signOut()
    router.push('/auth/login')
    router.refresh()
  }

  return (
    <header className="flex h-14 items-center gap-4 border-b px-4">
      <button
        type="button"
        onClick={() => setSidebarOpen(!sidebarOpen)}
        className="rounded-md p-1.5 hover:bg-accent"
        aria-label="Toggle sidebar">
        <PanelLeftIcon className="h-5 w-5" />
      </button>
      <div className="flex-1" />
      <span className="text-muted-foreground text-sm">{user.email}</span>
      <button
        type="button"
        onClick={handleLogout}
        className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm hover:bg-accent">
        <LogOutIcon className="h-4 w-4" />
        Sign out
      </button>
    </header>
  )
}
