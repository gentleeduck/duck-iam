'use client'

import { Avatar, AvatarFallback } from '@gentleduck/ui/avatar'
import { Badge } from '@gentleduck/ui/badge'
import { Button } from '@gentleduck/ui/button'
import { Card, CardContent } from '@gentleduck/ui/card'
import { FolderIcon } from 'lucide-react'
import Link from 'next/link'

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

export function WorkspaceList({ memberships }: { memberships: WorkspaceMembership[] }) {
  if (memberships.length === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <FolderIcon className="h-12 w-12 text-muted-foreground" />
          <p className="mt-3 text-muted-foreground text-sm">No workspaces yet</p>
          <Button asChild className="mt-4" size="sm">
            <Link href="/workspaces/new">Create your first workspace</Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {memberships.map(({ workspace, role }) => (
        <Link key={workspace.id} href={`/workspaces/${workspace.slug}`} className="group">
          <Card className="transition-all hover:border-primary/30 hover:shadow-md">
            <CardContent className="flex items-start justify-between p-4">
              <div className="flex min-w-0 items-center gap-3">
                <Avatar className="h-10 w-10 shrink-0 rounded-md">
                  <AvatarFallback className="rounded-md bg-primary/10 font-semibold text-primary">
                    {workspace.name.slice(0, 2).toUpperCase()}
                  </AvatarFallback>
                </Avatar>
                <div className="min-w-0">
                  <h3 className="truncate font-medium group-hover:underline">{workspace.name}</h3>
                  <p className="truncate text-muted-foreground text-xs">/{workspace.slug}</p>
                </div>
              </div>
              <Badge variant={roleBadgeVariant[role] ?? 'outline'} className="capitalize">
                {role}
              </Badge>
            </CardContent>
          </Card>
        </Link>
      ))}
    </div>
  )
}
