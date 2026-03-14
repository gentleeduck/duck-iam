'use client'

import { Avatar, AvatarFallback } from '@gentleduck/ui/avatar'
import { Badge } from '@gentleduck/ui/badge'
import { Button } from '@gentleduck/ui/button'
import { Card, CardContent } from '@gentleduck/ui/card'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@gentleduck/ui/context-menu'
import { ExternalLinkIcon, FolderIcon, SettingsIcon } from 'lucide-react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'

interface WorkspaceMembership {
  workspace: {
    id: string
    name: string
    slug: string
    ownerId: string
    createdAt: string
  }
  role: string
}

const roleBadgeVariant: Record<string, 'default' | 'secondary' | 'destructive' | 'outline' | 'warning'> = {
  owner: 'default',
  admin: 'warning',
  editor: 'secondary',
  viewer: 'outline',
}

const roleAccentColor: Record<string, string> = {
  owner: 'bg-pink-500',
  admin: 'bg-blue-500',
  editor: 'bg-green-500',
  viewer: 'bg-gray-400',
}

const avatarGradient: Record<string, string> = {
  owner: 'bg-gradient-to-br from-pink-500 to-rose-600',
  admin: 'bg-gradient-to-br from-blue-500 to-indigo-600',
  editor: 'bg-gradient-to-br from-green-500 to-emerald-600',
  viewer: 'bg-gradient-to-br from-gray-400 to-gray-500',
}

export function WorkspaceList({ memberships }: { memberships: WorkspaceMembership[] }) {
  const router = useRouter()

  if (memberships.length === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-16">
          <div className="rounded-full bg-muted p-4">
            <FolderIcon className="h-10 w-10 text-muted-foreground" />
          </div>
          <h3 className="mt-4 font-semibold text-base">No workspaces yet</h3>
          <p className="mt-1 text-muted-foreground text-sm">Create a workspace to get started</p>
          <Button asChild className="mt-5" size="sm">
            <Link href="/workspaces/new">Create your first workspace</Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))' }}>
      {memberships.map(({ workspace, role }) => (
        <ContextMenu key={workspace.id}>
          <ContextMenuTrigger asChild>
            <Link href={`/workspaces/${workspace.slug}`} className="group outline-none">
              <Card className="relative overflow-hidden transition-all duration-200 hover:scale-[1.02] hover:shadow-lg">
                <CardContent className="p-5">
                  <div className="flex items-start gap-4">
                    <Avatar className="h-12 w-12 shrink-0 rounded-xl shadow-sm">
                      <AvatarFallback
                        className={`rounded-xl font-bold text-base text-white ${avatarGradient[role] ?? 'bg-gradient-to-br from-gray-400 to-gray-500'}`}>
                        {workspace.name.charAt(0).toUpperCase()}
                      </AvatarFallback>
                    </Avatar>
                    <div className="min-w-0 flex-1">
                      <h3 className="truncate font-semibold text-base leading-tight transition-colors group-hover:text-primary">
                        {workspace.name}
                      </h3>
                      <p className="mt-0.5 truncate text-muted-foreground text-xs tracking-wide">/{workspace.slug}</p>
                    </div>
                    <Badge
                      variant={roleBadgeVariant[role] ?? 'outline'}
                      className="shrink-0 font-medium text-[11px] capitalize">
                      {role}
                    </Badge>
                  </div>
                </CardContent>
                <div className={`h-0.5 w-full ${roleAccentColor[role] ?? 'bg-gray-400'}`} />
              </Card>
            </Link>
          </ContextMenuTrigger>
          <ContextMenuContent className="w-48">
            <ContextMenuItem onSelect={() => router.push(`/workspaces/${workspace.slug}`)} className="gap-2">
              <ExternalLinkIcon className="h-4 w-4" />
              Open workspace
            </ContextMenuItem>
            <ContextMenuSeparator />
            <ContextMenuItem onSelect={() => router.push(`/workspaces/${workspace.slug}/settings`)} className="gap-2">
              <SettingsIcon className="h-4 w-4" />
              Settings
            </ContextMenuItem>
          </ContextMenuContent>
        </ContextMenu>
      ))}
    </div>
  )
}
